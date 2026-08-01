package deliver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coalaura/outboxd/internal/queue"
)

type enhancedCodeCase struct {
	code    int
	message string
	want    string
}

func servePlainSMTP(conn net.Conn, accepted chan<- struct{}, dataBytes chan<- string) {
	defer conn.Close()
	_, _ = io.WriteString(conn, "220 mx\r\n")
	r := bufio.NewReader(conn)

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}

		switch {
		case strings.HasPrefix(line, "EHLO"):
			_, _ = io.WriteString(conn, "250 mx\r\n")
		case strings.HasPrefix(line, "MAIL") || strings.HasPrefix(line, "RCPT"):
			_, _ = io.WriteString(conn, "250 ok\r\n")
		case strings.HasPrefix(line, "DATA"):
			_, _ = io.WriteString(conn, "354 go\r\n")
			if accepted != nil {
				accepted <- struct{}{}
			}

			var body strings.Builder

			for {
				line, err = r.ReadString('\n')
				body.WriteString(line)

				if err != nil {
					if dataBytes != nil {
						dataBytes <- body.String()
					}

					return
				}

				if strings.TrimRight(line, "\r\n") == "." {
					break
				}
			}

			_, _ = io.WriteString(conn, "250 queued\r\n")
		case strings.HasPrefix(line, "QUIT"):
			_, _ = io.WriteString(conn, "221 bye\r\n")
			return
		}
	}
}

func hardeningEnvelope(id string, created time.Time, recipients ...queue.Recipient) *queue.Envelope {
	return &queue.Envelope{
		ID: id, Username: "u", Sender: "sender@example.com", Recipients: recipients,
		Created: created, NextAttempt: created,
	}
}

func TestAttemptCancellationDoesNotConsumeFinalAttempt(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	cfg.Delivery.MaxAttempts = 1
	cfg.Delivery.CommandTimeout = "30s"
	d := New(cfg, q, nopLogger{})
	ip := net.ParseIP("127.0.0.1")
	d.SetResolver(&fixedResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com."}}},
		ips: map[string][]net.IP{"mx.ex.com": {ip}},
	})
	started := make(chan struct{})
	d.SetDialer(dialFn(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		close(started)
		go func() {
			defer server.Close()
			_, _ = server.Read(make([]byte, 1))
		}()
		return client, nil
	}))
	env := hardeningEnvelope("cancel-final", time.Now(), queue.Recipient{
		Address: "r@ex.com", Domain: "ex.com", Status: queue.StatusPending,
	})
	err = q.Add(env, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.attempt(ctx, got) }()
	<-started
	cancel()

	err = <-done
	if err != nil {
		t.Fatal(err)
	}

	if got.Attempts != 0 || got.Recipients[0].Status != queue.StatusPending {
		t.Fatalf("attempts=%d recipient=%+v", got.Attempts, got.Recipients[0])
	}

	if got.NextAttempt.After(time.Now()) {
		t.Fatalf("retry is not immediate: %s", got.NextAttempt)
	}

	dead, _ := q.DeadIDs()
	if len(dead) != 0 {
		t.Fatalf("cancellation buried message: %v", dead)
	}
}

func TestAttemptCancellationPreservesPartialMultiDomainProgress(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	cfg.Delivery.MaxAttempts = 1
	cfg.Delivery.CommandTimeout = "30s"
	d := New(cfg, q, nopLogger{})
	ipA, ipB := net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")
	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{
			"a.test": {{Host: "mx.a.test."}}, "b.test": {{Host: "mx.b.test."}},
		},
		ips: map[string][]net.IP{"mx.a.test": {ipA}, "mx.b.test": {ipB}},
	})
	stalled := make(chan struct{})
	d.SetDialer(dialFn(func(_ context.Context, _ string, address string) (net.Conn, error) {
		client, server := net.Pipe()
		host, _, _ := net.SplitHostPort(address)
		if host == ipA.String() {
			go servePlainSMTP(server, nil, nil)
		} else {
			close(stalled)
			go func() {
				defer server.Close()
				_, _ = server.Read(make([]byte, 1))
			}()
		}

		return client, nil
	}))
	now := time.Now()
	env := hardeningEnvelope("cancel-partial", now,
		queue.Recipient{Address: "a@a.test", Domain: "a.test", Status: queue.StatusPending},
		queue.Recipient{Address: "b@b.test", Domain: "b.test", Status: queue.StatusPending},
	)
	err = q.Add(env, []byte("hello\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	got, _ := q.Next(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.attempt(ctx, got) }()
	<-stalled
	cancel()

	err = <-done
	if err != nil {
		t.Fatal(err)
	}

	if got.Attempts != 0 || got.Recipients[0].Status != queue.StatusSent || got.Recipients[1].Status != queue.StatusPending {
		t.Fatalf("attempts=%d recipients=%+v", got.Attempts, got.Recipients)
	}
}

type failingBody struct {
	sent bool
}

func (r *failingBody) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, "partial body\r\n"), nil
	}

	return 0, errors.New("spool read failed")
}

func TestDataCopyErrorAbortsWithoutTerminator(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	d := New(testDeliverCfg(), q, nopLogger{})
	ip := net.ParseIP("127.0.0.1")
	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com."}}}, ips: map[string][]net.IP{"mx.ex.com": {ip}},
	})
	data := make(chan string, 1)
	d.SetDialer(dialFn(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go servePlainSMTP(server, nil, data)
		return client, nil
	}))
	d.reader = func(string) (io.ReadCloser, error) { return io.NopCloser(&failingBody{}), nil }
	env := hardeningEnvelope("copy-error", time.Now(), queue.Recipient{
		Address: "r@ex.com", Domain: "ex.com", Status: queue.StatusPending,
	})
	_, err = d.send(context.Background(), env, "mx.ex.com", []int{0})
	if err == nil {
		t.Fatal("expected body read error")
	}

	got := <-data
	if strings.Contains(got, "\r\n.\r\n") || strings.HasSuffix(got, ".\r\n") {
		t.Fatalf("DATA terminator was sent: %q", got)
	}
}

func TestEstablishedSessionClosesPromptlyOnCancel(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	d := New(testDeliverCfg(), q, nopLogger{})
	connected := make(chan struct{})
	d.SetDialer(dialFn(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		close(connected)
		go func() {
			defer server.Close()
			_, _ = server.Read(make([]byte, 1))
		}()
		return client, nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := d.dialAndSession(ctx, "mx.ex.com", net.ParseIP("127.0.0.1"), true); done <- err }()
	<-connected
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected canceled session error")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled established session ignored cancellation")
	}
}

func TestAttemptSessionCappedAtQueueLifetime(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	cfg.Delivery.MaximumLifetime = "100ms"
	cfg.Delivery.CommandTimeout = "30s"
	d := New(cfg, q, nopLogger{})
	d.SetResolver(&fixedResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com."}}},
		ips: map[string][]net.IP{"mx.ex.com": {net.ParseIP("127.0.0.1")}},
	})
	d.SetDialer(dialFn(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = server.Read(make([]byte, 1))
		}()
		return client, nil
	}))
	env := hardeningEnvelope("lifetime", time.Now(), queue.Recipient{
		Address: "r@ex.com", Domain: "ex.com", Status: queue.StatusPending,
	})
	err = q.Add(env, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	got, _ := q.Next(context.Background())
	start := time.Now()
	err = d.attempt(context.Background(), got)
	if err != nil {
		t.Fatal(err)
	}

	if time.Since(start) > time.Second {
		t.Fatal("queue lifetime did not cap session")
	}

	if got.Recipients[0].Status != queue.StatusFailed || got.Recipients[0].Detail != lifetimeDetail {
		t.Fatalf("recipient=%+v", got.Recipients[0])
	}
}

func TestSMTPResponseBounds(t *testing.T) {
	t.Run("exact boundary", func(t *testing.T) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = io.WriteString(server, "220 "+strings.Repeat("x", maxSMTPResponseBytes-6)+"\r\n")
		}()
		c := NewClient(client, time.Second, time.Second)
		defer c.Close()

		err := c.Greet()
		if err != nil {
			t.Fatalf("exact-boundary Greet error=%v", err)
		}
	})
	t.Run("banner", func(t *testing.T) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = io.WriteString(server, "220 "+strings.Repeat("x", maxSMTPResponseBytes)+"\r\n")
		}()
		c := NewClient(client, time.Second, time.Second)
		defer c.Close()

		err := c.Greet()
		if !errors.Is(err, errSMTPResponseTooLarge) {
			t.Fatalf("Greet error=%v", err)
		}
	})
	t.Run("multiline EHLO", func(t *testing.T) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = io.WriteString(server, "220 mx\r\n")
			r := bufio.NewReader(server)
			_, _ = r.ReadString('\n')

			for i := 0; i < maxSMTPResponseBytes/8+1; i++ {
				_, err := io.WriteString(server, "250-xxx\r\n")
				if err != nil {
					return
				}
			}

			_, _ = io.WriteString(server, "250 ok\r\n")
		}()
		c := NewClient(client, time.Second, time.Second)
		defer c.Close()

		err := c.Greet()
		if err != nil {
			t.Fatal(err)
		}

		err = c.EHLO("host")
		if !errors.Is(err, errSMTPResponseTooLarge) {
			t.Fatalf("EHLO error=%v", err)
		}
	})
}

func TestSubmissionDeadlineIncludesFinalDataResponse(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		line, err := r.ReadString('\n')
		if err != nil || line != "DATA\r\n" {
			return
		}

		_, _ = io.WriteString(server, "354 go\r\n")

		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}

			if line == ".\r\n" {
				break
			}
		}

		time.Sleep(75 * time.Millisecond)
		_, _ = io.WriteString(server, "250 queued\r\n")
	}()

	c := NewClient(client, time.Second, 100*time.Millisecond)
	defer c.Close()
	dw, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)

	_, err = io.WriteString(dw, "body\r\n")
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	err = dw.Close()
	if err == nil {
		t.Fatal("final response exceeded the DATA submission deadline")
	}

	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("deadline was reset during DATA close: %s", time.Since(start))
	}
}

func TestNormalizeDiagnostic(t *testing.T) {
	in := "bad\r\n\x00\x1f\x7f\u0085\u009b\u200b\u2028\u2029\u202e" + string([]byte{0xff}) + strings.Repeat("é", maxDiagnosticBytes)
	got := normalizeDiagnostic(in)
	if !utf8.ValidString(got) || len(got) > maxDiagnosticBytes {
		t.Fatalf("invalid normalized diagnostic: valid=%v bytes=%d", utf8.ValidString(got), len(got))
	}

	for _, r := range got {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			t.Fatalf("control %U remains in %q", r, got)
		}
	}

	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("multiline diagnostic: %q", got)
	}
}

func TestParseEnhancedCode(t *testing.T) {
	tests := []enhancedCodeCase{
		{550, "5.1.1 no such user", "5.1.1"},
		{451, "4.7.12 deferred", "4.7.12"},
		{550, "4.1.1 wrong class", ""},
		{550, "5.1000.1 too wide", ""},
		{550, "5.1 missing component", ""},
		{550, "rejected without enhanced code", ""},
	}

	for _, tt := range tests {
		got := parseEnhancedCode(tt.code, tt.message)
		if got != tt.want {
			t.Errorf("parseEnhancedCode(%d, %q)=%q want %q", tt.code, tt.message, got, tt.want)
		}
	}
}

func TestRestrictedDestinationTable(t *testing.T) {
	tests := map[string]bool{
		"100.64.0.1": true, "192.0.0.9": true, "198.19.255.255": true,
		"64:ff9b::0808:0808": true, "64:ff9b:1::1": true,
		"::ffff:10.0.0.1": true, "100:0:0:1::1": true, "3fff::1": true,
		"8.8.8.8": false, "1.1.1.1": false,
		"2606:4700:4700::1111": false, "2001:4860:4860::8888": false,
	}

	for raw, want := range tests {
		t.Run(raw, func(t *testing.T) {
			got := isRestricted(net.ParseIP(raw))
			if got != want {
				t.Fatalf("isRestricted(%s)=%v want %v", raw, got, want)
			}
		})
	}
}

func TestBackoffSaturates(t *testing.T) {
	d := &Deliverer{initial: time.Duration(1 << 62), maximum: time.Duration(1<<63 - 1)}

	for _, attempts := range []int{2, 10, 1000} {

		got := d.backoff(attempts)
		if got < 0 || got > d.maximum {
			t.Fatalf("backoff(%d)=%s", attempts, got)
		}
	}
}
