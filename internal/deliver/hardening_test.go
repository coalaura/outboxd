package deliver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

type dataLengthMismatchCase struct {
	name string
	body string
	want error
}

type domainErrorResolver struct{}

type resolverFuncs struct {
	mx  func(context.Context, string) ([]*net.MX, error)
	ips func(context.Context, string, string) ([]net.IP, error)
}

func (r resolverFuncs) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return r.mx(ctx, name)
}

func (r resolverFuncs) LookupNetIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return r.ips(ctx, network, host)
}

func (domainErrorResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, errors.New("temporary DNS failure for " + name)
}

func (domainErrorResolver) LookupNetIP(context.Context, string, string) ([]net.IP, error) {
	return nil, errors.New("unexpected address lookup")
}

type captureLog struct {
	mu    sync.Mutex
	lines strings.Builder
}

func (l *captureLog) Printf(format string, values ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Fprintf(&l.lines, format, values...)
}

func (l *captureLog) Debugf(format string, values ...any) {
	l.Printf(format, values...)
}

func (l *captureLog) Println(values ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Fprintln(&l.lines, values...)
}

func (l *captureLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.lines.String()
}

func TestOptionalDebugLogger(t *testing.T) {
	logger := new(captureLog)

	deliverer := &Deliverer{log: logger, debugLog: logger}

	deliverer.debugf("delivery timing: %s\n", time.Second)

	if got := logger.String(); got != "delivery timing: 1s\n" {
		t.Fatalf("debug log=%q", got)
	}
}

func TestDebugTrace(t *testing.T) {
	logger := new(captureLog)

	deliverer := &Deliverer{log: logger, debugLog: logger}

	trace := deliverer.newDebugTrace()

	trace.mark("phase")

	deliverer.debugf("trace: %s\n", trace)

	output := logger.String()
	if !strings.Contains(output, "phase=") || !strings.Contains(output, "total=") {
		t.Fatalf("trace log=%q", output)
	}

	disabled := (&Deliverer{}).newDebugTrace()

	disabled.mark("ignored")

	if disabled != nil {
		t.Fatalf("disabled trace initialized: %+v", disabled)
	}
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

			if dataBytes != nil {
				dataBytes <- body.String()
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
		ID: id, Username: "u",
		Sender:      "sender@example.com",
		Recipients:  recipients,
		Created:     created,
		NextAttempt: created,
	}
}

func TestAttemptCancellationDoesNotConsumeFinalAttempt(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

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

		go func() {
			defer server.Close()

			_, _ = io.WriteString(server, "220 mx\r\n")

			r := bufio.NewReader(server)

			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}

				switch {
				case strings.HasPrefix(line, "EHLO"):
					_, _ = io.WriteString(server, "250 mx\r\n")
				case strings.HasPrefix(line, "MAIL"):
					_, _ = io.WriteString(server, "250 ok\r\n")
				case strings.HasPrefix(line, "RCPT"):
					close(started)

					_, _ = server.Read(make([]byte, 1))

					return
				}
			}
		}()

		return client, nil
	}))

	env := hardeningEnvelope("cancel-final", time.Now(), queue.Recipient{
		Address: "r@ex.com",
		Domain:  "ex.com",
		Status:  queue.StatusPending,
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

	go func() {
		done <- d.attempt(ctx, got)
	}()

	<-started
	cancel()

	err = <-done
	if err != nil {
		t.Fatal(err)
	}

	if got.Attempts != 0 || got.Recipients[0].Status != queue.StatusPending {
		t.Fatalf("attempts=%d recipient=%+v", got.Attempts, got.Recipients[0])
	}

	if got.Recipients[0].Detail != "" || got.LastError != "" {
		t.Fatalf("cancellation diagnostics persisted: recipient=%q last=%q", got.Recipients[0].Detail, got.LastError)
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

	t.Cleanup(func() {
		_ = q.Close()
	})

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

	go func() {
		done <- d.attempt(ctx, got)
	}()

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

func TestAttemptSeparatesSameDomainBodyVariants(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	d := New(cfg, q, nopLogger{})

	d.SetResolver(&fixedResolver{
		mx:  map[string][]*net.MX{"example.com": {{Host: "mx.example.com."}}},
		ips: map[string][]net.IP{"mx.example.com": {net.ParseIP("127.0.0.1")}},
	})

	data := make(chan string, 2)

	var connections atomic.Int32

	d.SetDialer(dialFn(func(context.Context, string, string) (net.Conn, error) {
		connections.Add(1)

		client, server := net.Pipe()

		go servePlainSMTP(server, nil, data)

		return client, nil
	}))

	first := []byte("From: sender@example.com\r\n\r\nfirst\r\n")
	second := []byte("From: sender@example.com\r\n\r\nsecond\r\n")

	body := append(append([]byte(nil), first...), second...)

	now := time.Now()

	envelope := hardeningEnvelope("same-domain-variants", now,
		queue.Recipient{Address: "one@example.com", Domain: "example.com", Status: queue.StatusPending},
		queue.Recipient{Address: "two@example.com", Domain: "example.com", Body: 1, Status: queue.StatusPending},
	)

	envelope.Bodies = []queue.Body{
		queue.NewBody(0, first, false),
		queue.NewBody(int64(len(first)), second, false),
	}

	err = q.Add(envelope, body)
	if err != nil {
		t.Fatal(err)
	}

	queued, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = d.attempt(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}

	if connections.Load() != 2 || queued.Recipients[0].Status != queue.StatusSent || queued.Recipients[1].Status != queue.StatusSent {
		t.Fatalf("connections=%d recipients=%+v", connections.Load(), queued.Recipients)
	}

	got := []string{<-data, <-data}
	if !strings.Contains(got[0], "first") || strings.Contains(got[0], "second") || !strings.Contains(got[1], "second") || strings.Contains(got[1], "first") {
		t.Fatalf("delivered variants = %q", got)
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

	t.Cleanup(func() {
		_ = q.Close()
	})

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

	d.reader = func(string, int) (io.ReadCloser, error) { return io.NopCloser(&failingBody{}), nil }

	env := hardeningEnvelope("copy-error", time.Now(), queue.Recipient{
		Address: "r@ex.com",
		Domain:  "ex.com",
		Status:  queue.StatusPending,
	})

	env.Size = 100

	_, err = d.send(context.Background(), env, mxCandidate{host: "mx.ex.com"}, 0, []int{0})
	if err == nil || err.Error() != "spool read failed" {
		t.Fatalf("body read error=%v", err)
	}

	got := <-data
	if strings.Contains(got, "\r\n.\r\n") || strings.HasSuffix(got, ".\r\n") {
		t.Fatalf("DATA terminator was sent: %q", got)
	}
}

func TestDataLengthMismatchAbortsWithoutTerminator(t *testing.T) {
	for _, tt := range []dataLengthMismatchCase{
		{name: "short", body: "four", want: errBodyTooShort},
		{name: "long", body: "sixsix", want: errBodyTooLong},
	} {
		t.Run(tt.name, func(t *testing.T) {
			q, err := queue.Open(t.TempDir(), queue.Limits{})
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() {
				_ = q.Close()
			})

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

			d.reader = func(string, int) (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(tt.body)), nil
			}

			env := hardeningEnvelope("length-"+tt.name, time.Now(), queue.Recipient{
				Address: "r@ex.com", Domain: "ex.com", Status: queue.StatusPending,
			})

			env.Size = 5

			_, err = d.send(context.Background(), env, mxCandidate{host: "mx.ex.com"}, 0, []int{0})
			if !errors.Is(err, tt.want) {
				t.Fatalf("send error=%v want %v", err, tt.want)
			}

			got := <-data
			if strings.Contains(got, "\r\n.\r\n") || strings.HasSuffix(got, ".\r\n") {
				t.Fatalf("DATA terminator was sent: %q", got)
			}
		})
	}
}

func TestRunDomainAdmissionFairAtMinimumAttemptCapacity(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.DomainConcurrency = 1
	cfg.Delivery.GlobalConcurrency = 2
	cfg.Delivery.CommandTimeout = "30s"

	d := New(cfg, q, nopLogger{})

	if cap(d.active) != 8 {
		t.Fatalf("attempt capacity=%d want 8", cap(d.active))
	}

	hotIP := net.ParseIP("127.0.0.1")
	coldIP := net.ParseIP("127.0.0.2")

	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{
			"hot.test":  {{Host: "mx.hot.test."}},
			"cold.test": {{Host: "mx.cold.test."}},
		},
		ips: map[string][]net.IP{"mx.hot.test": {hotIP}, "mx.cold.test": {coldIP}},
	})

	coldAccepted := make(chan struct{}, 1)

	var (
		hotDials atomic.Int32
		hotOnce  sync.Once
	)

	hotStarted := make(chan struct{})

	d.SetDialer(dialFn(func(_ context.Context, _ string, address string) (net.Conn, error) {
		client, server := net.Pipe()

		host, _, _ := net.SplitHostPort(address)
		if host == hotIP.String() {
			hotDials.Add(1)

			hotOnce.Do(func() {
				close(hotStarted)
			})

			go func() {
				defer server.Close()

				_, _ = server.Read(make([]byte, 1))
			}()
		} else {
			go servePlainSMTP(server, coldAccepted, nil)
		}

		return client, nil
	}))

	now := time.Now()

	for i := 0; i < cap(d.active); i++ {
		env := hardeningEnvelope(fmt.Sprintf("hot-%02d", i), now, queue.Recipient{
			Address: "r@hot.test", Domain: "hot.test", Status: queue.StatusPending,
		})

		err = q.Add(env, []byte("body\r\n"))
		if err != nil {
			t.Fatal(err)
		}
	}

	cold := hardeningEnvelope("cold", now, queue.Recipient{
		Address: "r@cold.test", Domain: "cold.test", Status: queue.StatusPending,
	})

	err = q.Add(cold, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- d.Run(ctx)
	}()

	select {
	case <-hotStarted:
	case <-time.After(time.Second):
		cancel()
		<-done

		t.Fatal("hot-domain attempt did not start")
	}

	select {
	case <-coldAccepted:
	case <-time.After(2 * time.Second):
		cancel()
		<-done

		t.Fatal("cold domain was starved by hot-domain waiters")
	}

	got := hotDials.Load()
	if got != 1 {
		cancel()
		<-done

		t.Fatalf("hot-domain dials=%d want 1", got)
	}

	cancel()

	if err := <-done; err != nil {
		t.Fatal(err)
	}

	for i := 0; i < cap(d.active); i++ {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)

		env, err := q.Next(ctx)

		stop()

		if err != nil {
			t.Fatal(err)
		}

		if env.Attempts != 0 {
			t.Fatalf("admission/cancellation consumed attempt for %s: %d", env.ID, env.Attempts)
		}
	}
}

func TestInitialAdmissionParksUntilRelease(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.UserConcurrency = 1

	d := New(cfg, q, nopLogger{})

	if !d.users.tryAcquire("user") {
		t.Fatal("failed to reserve user capacity")
	}

	envelope := hardeningEnvelope("parked-admission", time.Now(), queue.Recipient{
		Address: "r@example.test", Domain: "example.test", Status: queue.StatusPending,
	})

	envelope.Username = "user"

	err = q.Add(envelope, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	checkedOut, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	d.parkAdmission(checkedOut, admissionUser, "user")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)

	parked, err := q.Next(ctx)

	cancel()

	if !errors.Is(err, context.DeadlineExceeded) || parked != nil {
		t.Fatalf("parked entry was scheduled: envelope=%v err=%v", parked, err)
	}

	d.users.release("user")

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)

	resumed, err := q.Next(ctx)

	cancel()

	if err != nil {
		t.Fatal(err)
	}

	if resumed.ID != envelope.ID || resumed.Attempts != 0 {
		t.Fatalf("resumed envelope=%+v", resumed)
	}

	q.Requeue(resumed)
}

func TestRunMixedDomainAdmissionDoesNotCaptureLaterDomainCapacity(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.DomainConcurrency = 1
	cfg.Delivery.CommandTimeout = "30s"

	d := New(cfg, q, nopLogger{})

	firstIP := net.ParseIP("127.0.0.1")

	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{
			"first.test": {{Host: "mx.first.test."}},
			"later.test": {{Host: "mx.later.test."}},
		},
		ips: map[string][]net.IP{
			"mx.first.test": {firstIP},
			"mx.later.test": {net.ParseIP("127.0.0.2")},
		},
	})

	firstStarted := make(chan struct{})

	d.SetDialer(dialFn(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()

		close(firstStarted)

		go func() {
			defer server.Close()

			_, _ = server.Read(make([]byte, 1))
		}()

		return client, nil
	}))

	now := time.Now()

	env := hardeningEnvelope("mixed-admission", now,
		queue.Recipient{Address: "a@first.test", Domain: "first.test", Status: queue.StatusPending},
		queue.Recipient{Address: "b@later.test", Domain: "later.test", Status: queue.StatusPending},
	)

	err = q.Add(env, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- d.Run(ctx)
	}()

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		cancel()
		<-done

		t.Fatal("first domain did not start")
	}

	if !d.domains.tryAcquire("later.test") {
		cancel()
		<-done

		t.Fatal("slow first domain captured later domain capacity")
	}

	d.domains.release("later.test")

	cancel()

	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAttemptTemporaryFirstDomainAndBusyLaterParksUntilRelease(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.DomainConcurrency = 1
	cfg.Delivery.InitialRetryDelay = "1h"
	cfg.Delivery.MaximumRetryDelay = "1h"

	d := New(cfg, q, nopLogger{})

	d.SetResolver(domainErrorResolver{})

	if !d.domains.tryAcquire("busy.test") {
		t.Fatal("failed to reserve busy domain")
	}

	now := time.Now()

	env := &queue.Envelope{
		ID:       "later-domain-contention",
		Username: "u",
		Sender:   "sender@example.com",
		Recipients: []queue.Recipient{
			{Address: "a@temporary.test", Domain: "temporary.test", Status: queue.StatusPending},
			{Address: "b@busy.test", Domain: "busy.test", Status: queue.StatusPending},
		},
		Created:     now,
		NextAttempt: now,
	}

	err = q.Add(env, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = d.attempt(context.Background(), got)
	if err != nil {
		t.Fatal(err)
	}

	if got.Attempts != 1 {
		t.Fatalf("attempt accounting=%d want 1", got.Attempts)
	}

	if got.Recipients[0].Status != queue.StatusPending || !strings.Contains(got.Recipients[0].Detail, "temporary DNS failure") {
		t.Fatalf("first domain outcome not preserved: %+v", got.Recipients[0])
	}

	if got.Recipients[1].Status != queue.StatusPending || got.Recipients[1].Detail != "" {
		t.Fatalf("busy later domain was processed: %+v", got.Recipients[1])
	}

	if !strings.Contains(got.LastError, "temporary.test") || strings.Contains(got.LastError, "delivery concurrency unavailable") {
		t.Fatalf("aggregate diagnostic=%q", got.LastError)
	}

	if got.NextAttempt.After(time.Now().Add(time.Second)) {
		t.Fatalf("later-domain contention applied delivery backoff: %s", got.NextAttempt.Sub(now))
	}

	d.domains.release("busy.test")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resumed, err := q.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if resumed.PreferredDomain != "busy.test" || nextPendingDomain(resumed) != "busy.test" {
		t.Fatalf("resumed domain=%q preferred=%q", nextPendingDomain(resumed), resumed.PreferredDomain)
	}

	q.Requeue(resumed)
}

func TestAttemptAllTemporaryRCPTPreservesDetailsAndAggregateDiagnostic(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	log := new(captureLog)

	d := New(cfg, q, log)

	ip := net.ParseIP("127.0.0.1")

	d.SetResolver(&fixedResolver{
		mx:  map[string][]*net.MX{"temp.test": {{Host: "mx.temp.test."}}},
		ips: map[string][]net.IP{"mx.temp.test": {ip}},
	})

	d.SetDialer(dialFn(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()

		go func() {
			defer server.Close()

			_, _ = io.WriteString(server, "220 mx\r\n")

			r := bufio.NewReader(server)

			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}

				switch {
				case strings.HasPrefix(line, "EHLO"):
					_, _ = io.WriteString(server, "250 mx\r\n")
				case strings.HasPrefix(line, "MAIL"):
					_, _ = io.WriteString(server, "250 ok\r\n")
				case strings.HasPrefix(line, "RCPT"):
					_, _ = io.WriteString(server, "451 4.7.1 greylisted\r\n")
				case strings.HasPrefix(line, "QUIT"):
					_, _ = io.WriteString(server, "221 bye\r\n")

					return
				}
			}
		}()

		return client, nil
	}))

	now := time.Now()

	env := hardeningEnvelope("temporary-rcpt", now,
		queue.Recipient{Address: "a@temp.test", Domain: "temp.test", Status: queue.StatusPending},
		queue.Recipient{Address: "b@temp.test", Domain: "temp.test", Status: queue.StatusPending},
	)

	err = q.Add(env, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = d.attempt(context.Background(), got)
	if err != nil {
		t.Fatal(err)
	}

	for _, recipient := range got.Recipients {
		if recipient.Status != queue.StatusPending || !strings.Contains(recipient.Detail, "451 4.7.1 greylisted") {
			t.Fatalf("temporary recipient outcome not preserved: %+v", recipient)
		}
	}

	for _, diagnostic := range []string{"temporary RCPT failures", "a@temp.test", "b@temp.test", "451 4.7.1 greylisted"} {
		if !strings.Contains(got.LastError, diagnostic) {
			t.Fatalf("LastError=%q missing %q", got.LastError, diagnostic)
		}

		if !strings.Contains(log.String(), diagnostic) {
			t.Fatalf("log=%q missing %q", log.String(), diagnostic)
		}
	}
}

func TestAttemptPreservesPerDomainDiagnosticsAndAggregateLog(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.MaxAttempts = 1

	log := new(captureLog)

	d := New(cfg, q, log)

	d.SetResolver(domainErrorResolver{})

	now := time.Now()

	env := &queue.Envelope{
		ID:       "domain-diagnostics",
		Username: "u",
		Sender:   "sender@example.com",
		Recipients: []queue.Recipient{
			{Address: "a@a.test", Domain: "a.test", Status: queue.StatusPending},
			{Address: "b@b.test", Domain: "b.test", Status: queue.StatusPending},
		},
		Created:     now,
		NextAttempt: now,
	}

	err = q.Add(env, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = d.attempt(context.Background(), got)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(got.Recipients[0].Detail, "a.test") || strings.Contains(got.Recipients[0].Detail, "b.test") {
		t.Fatalf("first recipient detail copied across domains: %q", got.Recipients[0].Detail)
	}

	if !strings.Contains(got.Recipients[1].Detail, "b.test") || strings.Contains(got.Recipients[1].Detail, "a.test") {
		t.Fatalf("second recipient detail copied across domains: %q", got.Recipients[1].Detail)
	}

	for _, recipient := range got.Recipients {
		if recipient.EnhancedCode != terminalEnhancedCode {
			t.Fatalf("recipient missing exhaustion status: %+v", recipient)
		}
	}

	if !strings.Contains(got.LastError, "a.test") || !strings.Contains(got.LastError, "b.test") {
		t.Fatalf("aggregate diagnostic=%q", got.LastError)
	}

	output := log.String()
	if !strings.Contains(output, "a.test") || !strings.Contains(output, "b.test") {
		t.Fatalf("aggregate log missing domain diagnostics: %q", output)
	}
}

func TestEstablishedSessionClosesPromptlyOnCancel(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	log := new(captureLog)

	d := New(testDeliverCfg(), q, log)

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

	go func() {
		_, err := d.dialAndSession(ctx, "mx.ex.com", net.ParseIP("127.0.0.1"), true)

		done <- err
	}()

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

	t.Cleanup(func() {
		_ = q.Close()
	})

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
		Address: "r@ex.com",
		Domain:  "ex.com",
		Status:  queue.StatusPending,
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

	if got.Recipients[0].Status != queue.StatusFailed || got.Recipients[0].Detail != lifetimeDetail || got.Recipients[0].EnhancedCode != terminalEnhancedCode {
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

			for range maxSMTPResponseBytes/8 + 1 {
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

func TestRunQuarantinesCorruptBodyAndContinues(t *testing.T) {
	root := t.TempDir()

	q, err := queue.Open(root, queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	now := time.Now()

	corrupt := hardeningEnvelope("corrupt-runtime", now, queue.Recipient{Address: "r@bad.test", Domain: "bad.test", Status: queue.StatusPending})
	healthy := hardeningEnvelope("healthy-runtime", now, queue.Recipient{Address: "r@good.test", Domain: "good.test", Status: queue.StatusPending})

	healthy.Username = "other-user"

	err = q.Add(corrupt, []byte("body-a\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	err = q.Add(healthy, []byte("body-b\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(root, "ready", corrupt.ID, "message.eml"), []byte("body-x\r\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}

	log := new(captureLog)

	d := New(testDeliverCfg(), q, log)

	badIP, goodIP := net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")

	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{
			"bad.test":  {{Host: "mx.bad.test."}},
			"good.test": {{Host: "mx.good.test."}},
		},
		ips: map[string][]net.IP{"mx.bad.test": {badIP}, "mx.good.test": {goodIP}},
	})

	healthyAccepted := make(chan struct{}, 1)

	d.SetDialer(dialFn(func(_ context.Context, _ string, address string) (net.Conn, error) {
		client, server := net.Pipe()

		host, _, _ := net.SplitHostPort(address)
		if host == goodIP.String() {
			go servePlainSMTP(server, healthyAccepted, nil)
		} else {
			go servePlainSMTP(server, nil, nil)
		}

		return client, nil
	}))

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- d.Run(ctx)
	}()

	select {
	case <-healthyAccepted:
	case <-time.After(time.Second):
		cancel()
		<-done

		t.Fatal("healthy delivery was blocked by corrupt queue item")
	}

	deadline := time.Now().Add(5 * time.Second)

	var quarantined bool

	for time.Now().Before(deadline) {
		ids, listErr := q.CorruptIDs()
		if listErr != nil {
			cancel()
			<-done

			t.Fatal(listErr)
		}

		messages, _ := q.Stats()
		if len(ids) == 1 && messages == 0 {
			quarantined = true

			break
		}

		time.Sleep(time.Millisecond)
	}

	if !quarantined {
		cancel()
		<-done

		ids, _ := q.CorruptIDs()
		messages, _ := q.Stats()

		t.Fatalf("queue messages=%d corrupt entries=%v after healthy completion and quarantine", messages, ids)
	}

	select {
	case err := <-done:
		t.Fatalf("Run stopped after item corruption: %v", err)
	default:
	}

	cancel()

	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if len(q.Corrupt) != 1 || !queue.IsCorruption(q.Corrupt[0]) {
		t.Fatalf("corrupt records=%v log=%s", q.Corrupt, log.String())
	}
}

func TestPerUserDeliveryIsolation(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.UserConcurrency = 1
	cfg.Delivery.DomainConcurrency = 2
	cfg.Delivery.GlobalConcurrency = 2
	cfg.Delivery.CommandTimeout = "30s"

	d := New(cfg, q, nopLogger{})

	d.admission = 5 * time.Millisecond

	ips := map[string]net.IP{
		"mx.a1.test": net.ParseIP("127.0.0.1"),
		"mx.a2.test": net.ParseIP("127.0.0.2"),
		"mx.b.test":  net.ParseIP("127.0.0.3"),
	}

	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{
			"a1.test": {{Host: "mx.a1.test."}},
			"a2.test": {{Host: "mx.a2.test."}},
			"b.test":  {{Host: "mx.b.test."}},
		},
		ips: map[string][]net.IP{"mx.a1.test": {ips["mx.a1.test"]}, "mx.a2.test": {ips["mx.a2.test"]}, "mx.b.test": {ips["mx.b.test"]}},
	})

	var aDials atomic.Int32

	aStarted := make(chan struct{}, 1)
	bAccepted := make(chan struct{}, 1)

	d.SetDialer(dialFn(func(_ context.Context, _ string, address string) (net.Conn, error) {
		client, server := net.Pipe()

		host, _, _ := net.SplitHostPort(address)
		if host == ips["mx.b.test"].String() {
			go servePlainSMTP(server, bAccepted, nil)

			return client, nil
		}

		aDials.Add(1)

		select {
		case aStarted <- struct{}{}:
		default:
		}

		go func() {
			defer server.Close()

			_, _ = server.Read(make([]byte, 1))
		}()

		return client, nil
	}))

	now := time.Now()

	add := func(id, username, domain string) {
		env := hardeningEnvelope(id, now, queue.Recipient{Address: "r@" + domain, Domain: domain, Status: queue.StatusPending})

		env.Username = username

		err := q.Add(env, []byte("body\r\n"))
		if err != nil {
			t.Fatal(err)
		}
	}

	add("a-one", "user-a", "a1.test")
	add("a-two", "user-a", "a2.test")
	add("b-one", "user-b", "b.test")

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- d.Run(ctx)
	}()

	select {
	case <-aStarted:
	case <-time.After(time.Second):
		cancel()
		<-done

		t.Fatal("user A did not start")
	}

	select {
	case <-bAccepted:
	case <-time.After(time.Second):
		cancel()
		<-done

		t.Fatal("user B was starved by stalled user A")
	}

	got := aDials.Load()
	if got != 1 {
		cancel()
		<-done

		t.Fatalf("user A active dials=%d want 1", got)
	}

	cancel()

	if err := <-done; err != nil {
		t.Fatal(err)
	}

	ordinary := &queue.Envelope{Username: "mailer-daemon"}

	dsn := &queue.Envelope{Username: "mailer-daemon", DSNSourceID: "source"}

	if deliveryOwner(ordinary) == deliveryOwner(dsn) || deliveryOwner(dsn) != generatedDSNOwner {
		t.Fatal("generated DSN owner is not isolated from ordinary users")
	}
}

func TestCandidateCeilings(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.MaxMXCandidates = 3
	cfg.Delivery.MaxIPCandidatesPerMX = 2

	d := New(cfg, q, nopLogger{})

	var addressLookups, dials atomic.Int32

	d.SetResolver(resolverFuncs{
		mx: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{
				{Host: "MX-01.test.", Pref: 10}, {Host: "mx-01.test.", Pref: 20},
				{Host: "mx-04.test.", Pref: 10}, {Host: "mx-03.test.", Pref: 10},
				{Host: "mx-02.test.", Pref: 10}, {Host: "mx-00.test.", Pref: 10},
			}, nil
		},
		ips: func(_ context.Context, _, host string) ([]net.IP, error) {
			addressLookups.Add(1)

			return []net.IP{
				net.ParseIP("8.8.8.4"), net.ParseIP("8.8.8.3"), net.ParseIP("8.8.8.2"),
				net.ParseIP("8.8.8.1"), net.ParseIP("8.8.8.1"),
			}, nil
		},
	})

	d.SetDialer(dialFn(func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)

		return nil, errors.New("blocked")
	}))

	env := hardeningEnvelope("candidate-cap", time.Now(), queue.Recipient{Address: "r@test", Domain: "test", Status: queue.StatusPending})

	err = d.domain(context.Background(), env, "test", 0, []int{0})
	if err == nil {
		t.Fatal("expected candidate failures")
	}

	got := addressLookups.Load()
	if got != 3 {
		t.Fatalf("address lookups=%d want 3", got)
	}

	got = dials.Load()
	if got != 6 {
		t.Fatalf("dials=%d want 6", got)
	}
}

func TestMXEqualPreferenceOrderingBeforeTruncation(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.MaxMXCandidates = 4

	d := New(cfg, q, nopLogger{})

	d.SetResolver(resolverFuncs{
		mx: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{
				{Host: "e.test.", Pref: 20}, {Host: "c.test.", Pref: 10},
				{Host: "d.test.", Pref: 20}, {Host: "a.test.", Pref: 10},
				{Host: "b.test.", Pref: 10}, {Host: "a.test.", Pref: 30},
			}, nil
		},
		ips: func(context.Context, string, string) ([]net.IP, error) {
			return nil, errors.New("unexpected address lookup")
		},
	})

	groups := make([]uint16, 0, 3)

	d.orderMX = func(records []*net.MX) {
		groups = append(groups, records[0].Pref)

		for left, right := 0, len(records)-1; left < right; left, right = left+1, right-1 {
			records[left], records[right] = records[right], records[left]
		}
	}

	hosts, err := d.hosts(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}

	if got, want := candidateHostList(hosts), "c.test,b.test,a.test,e.test"; got != want {
		t.Fatalf("MX cap/order=%q want %q", got, want)
	}

	if fmt.Sprint(groups) != "[10 20 30]" {
		t.Fatalf("preference groups=%v", groups)
	}
}

func TestMXMixedWithNullMXFails(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	d := New(testDeliverCfg(), q, nopLogger{})

	d.SetResolver(resolverFuncs{
		mx: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{{Host: "."}, {Host: "mx.example."}}, nil
		},
		ips: func(context.Context, string, string) ([]net.IP, error) {
			return nil, errors.New("unexpected address lookup")
		},
	})

	_, err = d.hosts(context.Background(), "example")
	if !errors.Is(err, errNullMX) {
		t.Fatalf("mixed null MX error=%v, want errNullMX", err)
	}
}

func TestMXEqualPreferenceCandidatesCanRotateAcrossRetries(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.MaxMXCandidates = 2

	d := New(cfg, q, nopLogger{})

	d.SetResolver(resolverFuncs{
		mx: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{
				{Host: "d.test.", Pref: 10}, {Host: "b.test.", Pref: 10},
				{Host: "a.test.", Pref: 10}, {Host: "c.test.", Pref: 10},
			}, nil
		},
		ips: func(context.Context, string, string) ([]net.IP, error) {
			return nil, errors.New("unexpected address lookup")
		},
	})

	var calls int

	d.orderMX = func(records []*net.MX) {
		calls++

		if len(records) != 4 {
			t.Fatalf("orderMX received %d candidates before truncation", len(records))
		}

		if calls == 1 {
			for left, right := 0, len(records)-1; left < right; left, right = left+1, right-1 {
				records[left], records[right] = records[right], records[left]
			}
		}
	}

	first, err := d.hosts(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}

	second, err := d.hosts(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}

	if got, want := candidateHostList(first), "d.test,c.test"; got != want {
		t.Fatalf("first retry MXs=%q want %q", got, want)
	}

	if got, want := candidateHostList(second), "a.test,b.test"; got != want {
		t.Fatalf("second retry MXs=%q want %q", got, want)
	}
}

func candidateHostList(candidates []mxCandidate) string {
	hosts := make([]string, len(candidates))

	for i, candidate := range candidates {
		hosts[i] = candidate.host
	}

	return strings.Join(hosts, ",")
}

func TestClientQuitDoesNotWaitForReply(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	client := NewClient(clientConn, 5*time.Second, 5*time.Second)

	received := make(chan string, 1)
	release := make(chan struct{})

	go func() {
		defer serverConn.Close()

		line, _ := bufio.NewReader(serverConn).ReadString('\n')
		received <- strings.TrimSpace(line)

		<-release
	}()

	done := make(chan error, 1)

	go func() {
		done <- client.Quit()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("QUIT waited for a server reply")
	}

	if line := <-received; line != "QUIT" {
		t.Fatalf("command=%q want QUIT", line)
	}

	close(release)
}

func TestClientRcptBatchPipelinesCommands(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	client := NewClient(clientConn, 5*time.Second, 5*time.Second)

	go func() {
		defer serverConn.Close()

		reader := bufio.NewReader(serverConn)

		for range 2 {
			_, _ = reader.ReadString('\n')
		}

		_, _ = io.WriteString(serverConn, "250 2.1.5 accepted\r\n550 5.1.1 rejected\r\n")
	}()

	results, err := client.RcptBatch([]string{"one@example.test", "two@example.test"})
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 2 || results[0] != nil || !permanent(results[1]) {
		t.Fatalf("RCPT results=%v", results)
	}
}

func TestClientRcptBatchReturnsReceivedResponsesBeforeTransportFailure(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	client := NewClient(clientConn, 5*time.Second, 5*time.Second)

	go func() {
		reader := bufio.NewReader(serverConn)

		for range 3 {
			_, _ = reader.ReadString('\n')
		}

		_, _ = io.WriteString(serverConn, "250 2.1.5 accepted\r\n451 4.3.0 temporary\r\n")
		_ = serverConn.Close()
	}()

	results, err := client.RcptBatch([]string{"one@example.test", "two@example.test", "three@example.test"})
	if err == nil {
		t.Fatal("RCPT batch succeeded after truncated replies")
	}

	if len(results) != 3 || results[0] != nil || permanent(results[1]) || smtpCode(results[1]) != 451 || smtpCode(results[2]) != 0 {
		t.Fatalf("RCPT results=%v err=%v", results, err)
	}
}

func TestImplicitMXReusesFilteredAddresses(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	d := New(testDeliverCfg(), q, nopLogger{})

	var addressLookups atomic.Int32

	d.SetResolver(resolverFuncs{
		mx: func(context.Context, string) ([]*net.MX, error) {
			return nil, &net.DNSError{IsNotFound: true}
		},
		ips: func(context.Context, string, string) ([]net.IP, error) {
			addressLookups.Add(1)

			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	})

	candidates, err := d.hosts(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}

	if addressLookups.Load() != 1 || len(candidates) != 1 || len(candidates[0].ips) != 1 {
		t.Fatalf("lookups=%d candidates=%v", addressLookups.Load(), candidates)
	}
}

func TestRestrictedAddressesDoNotConsumeCandidateBudget(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.AllowPrivateDestinations = false
	cfg.Delivery.MaxIPCandidatesPerMX = 1

	d := New(cfg, q, nopLogger{})

	d.orderIPs = func([]net.IP) {}

	d.SetResolver(resolverFuncs{
		mx: func(context.Context, string) ([]*net.MX, error) {
			return nil, errors.New("unexpected MX lookup")
		},
		ips: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("100.64.0.1"),
				net.ParseIP("127.0.0.1"),
				net.ParseIP("169.254.1.1"),
				net.ParseIP("172.16.0.1"),
				net.ParseIP("192.168.0.1"),
				net.ParseIP("198.18.0.1"),
				net.ParseIP("224.0.0.1"),
				net.ParseIP("8.8.8.8"),
			}, nil
		},
	})

	ips, err := d.lookupHostIPs(context.Background(), "mx.test")
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("eligible candidates=%v", ips)
	}
}

func TestIPOrderingRunsBeforeTruncationAndRotatesRetries(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.MaxIPCandidatesPerMX = 2

	d := New(cfg, q, nopLogger{})

	d.SetResolver(resolverFuncs{
		mx: func(context.Context, string) ([]*net.MX, error) {
			return nil, errors.New("unexpected MX lookup")
		},
		ips: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{
				net.ParseIP("8.8.8.1"), net.ParseIP("8.8.8.2"),
				net.ParseIP("8.8.8.3"), net.ParseIP("8.8.8.4"),
			}, nil
		},
	})

	var calls int

	d.orderIPs = func(ips []net.IP) {
		calls++

		if len(ips) != 4 {
			t.Fatalf("orderIPs received %d candidates before truncation", len(ips))
		}

		if calls == 1 {
			for left, right := 0, len(ips)-1; left < right; left, right = left+1, right-1 {
				ips[left], ips[right] = ips[right], ips[left]
			}
		}
	}

	first, err := d.lookupHostIPs(context.Background(), "mx.test")
	if err != nil {
		t.Fatal(err)
	}

	second, err := d.lookupHostIPs(context.Background(), "mx.test")
	if err != nil {
		t.Fatal(err)
	}

	if calls != 2 || len(first) != 2 || len(second) != 2 || first[0].Equal(second[0]) {
		t.Fatalf("retry candidates first=%v second=%v calls=%d", first, second, calls)
	}
}

func TestAttemptTimeoutIsNormalFailure(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = q.Close()
	})

	cfg := testDeliverCfg()

	cfg.Delivery.AttemptTimeout = "50ms"
	cfg.Delivery.DNSTimeout = "5s"

	d := New(cfg, q, nopLogger{})

	d.SetResolver(resolverFuncs{
		mx: func(ctx context.Context, _ string) ([]*net.MX, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		ips: func(context.Context, string, string) ([]net.IP, error) {
			return nil, errors.New("unexpected lookup")
		},
	})

	env := hardeningEnvelope("attempt-timeout", time.Now(), queue.Recipient{Address: "r@ex.test", Domain: "ex.test", Status: queue.StatusPending})

	err = q.Add(env, []byte("body\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = d.attempt(context.Background(), got)
	if err != nil {
		t.Fatal(err)
	}

	if got.Attempts != 1 || got.Recipients[0].Status != queue.StatusPending || !strings.Contains(got.LastError, errAttemptTimeout.Error()) {
		t.Fatalf("timed-out attempt=%+v", got)
	}
}

func TestBlockedOutboundWorkDoesNotBlockUnrelatedDelivery(t *testing.T) {
	for _, mode := range []string{"resolver", "dial"} {
		t.Run(mode, func(t *testing.T) {
			q, err := queue.Open(t.TempDir(), queue.Limits{})
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() {
				_ = q.Close()
			})

			cfg := testDeliverCfg()

			cfg.Delivery.DNSTimeout = "60ms"
			cfg.Delivery.ConnectionTimeout = "60ms"
			cfg.Delivery.AttemptTimeout = "150ms"
			cfg.Delivery.GlobalConcurrency = 2

			d := New(cfg, q, nopLogger{})

			badIP, goodIP := net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")

			blockedDone := make(chan struct{}, 1)

			d.SetResolver(resolverFuncs{
				mx: func(ctx context.Context, name string) ([]*net.MX, error) {
					if name == "bad.test" && mode == "resolver" {
						<-ctx.Done()

						blockedDone <- struct{}{}

						return nil, ctx.Err()
					}

					return []*net.MX{{Host: "mx." + name + "."}}, nil
				},
				ips: func(_ context.Context, _ string, host string) ([]net.IP, error) {
					if host == "mx.bad.test" {
						return []net.IP{badIP}, nil
					}

					return []net.IP{goodIP}, nil
				},
			})

			goodAccepted := make(chan struct{}, 1)

			d.SetDialer(dialFn(func(ctx context.Context, _ string, address string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(address)
				if host == badIP.String() {
					<-ctx.Done()

					blockedDone <- struct{}{}

					return nil, ctx.Err()
				}

				client, server := net.Pipe()

				go servePlainSMTP(server, goodAccepted, nil)

				return client, nil
			}))

			now := time.Now()

			bad := hardeningEnvelope("blocked-"+mode, now, queue.Recipient{Address: "r@bad.test", Domain: "bad.test", Status: queue.StatusPending})

			bad.Username = "bad-user"

			good := hardeningEnvelope("unrelated-"+mode, now, queue.Recipient{Address: "r@good.test", Domain: "good.test", Status: queue.StatusPending})

			good.Username = "good-user"

			err = q.Add(bad, []byte("body\r\n"))
			if err != nil {
				t.Fatal(err)
			}

			err = q.Add(good, []byte("body\r\n"))
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(context.Background())

			done := make(chan error, 1)

			go func() {
				done <- d.Run(ctx)
			}()

			select {
			case <-goodAccepted:
			case <-time.After(time.Second):
				cancel()
				<-done

				t.Fatal("unrelated delivery was blocked")
			}

			select {
			case <-blockedDone:
			case <-time.After(time.Second):
				cancel()
				<-done

				t.Fatal("blocked operation ignored its deadline")
			}

			cancel()

			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
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
		"fec0::1": true, "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff": true,
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
