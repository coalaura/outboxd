package rejection

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
)

type testLogger struct{}

func (testLogger) Printf(string, ...any) {}

func (testLogger) Println(...any) {}

type captureLogger struct {
	mu  sync.Mutex
	out strings.Builder
}

func (l *captureLogger) Printf(format string, values ...any) {
	l.mu.Lock()
	fmt.Fprintf(&l.out, format, values...)
	l.mu.Unlock()
}

func (l *captureLogger) Println(values ...any) {
	l.mu.Lock()
	fmt.Fprintln(&l.out, values...)
	l.mu.Unlock()
}

func (l *captureLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.out.String()
}

func testServer(t *testing.T, mode string) (*Server, context.CancelFunc, <-chan error) {
	t.Helper()

	cfg := config.Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.ReplyRejection.Enabled = true
	cfg.ReplyRejection.ListenAddr = "127.0.0.1:0"
	cfg.ReplyRejection.UnknownRecipients = mode
	cfg.ReplyRejection.Domains = []string{"example.com"}
	cfg.ReplyRejection.DefaultMessage = "This address does not accept replies"
	cfg.ReplyRejection.Recipients = []config.ReplyRejectionRecipient{
		{Address: "noreply@example.com", Message: "Contact support@example.com"},
		{Address: "updates@example.com"},
	}

	err := cfg.Validate()
	if err != nil {
		t.Fatal(err)
	}

	srv := New(cfg, testLogger{})

	err = srv.Listen()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- srv.Run(ctx)
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not stop")
		}
	})

	return srv, cancel, done
}

func smtpCommand(t *testing.T, srv *Server, recipient string) string {
	t.Helper()

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	reader := bufio.NewReader(conn)

	readResponse(t, reader, "220")

	fmt.Fprintf(conn, "EHLO sender.example\r\n")
	readResponse(t, reader, "250")

	fmt.Fprintf(conn, "MAIL FROM:<sender@example.net>\r\n")
	readResponse(t, reader, "250")

	fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", recipient)

	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}

	return strings.TrimSpace(response)
}

func readResponse(t *testing.T, reader *bufio.Reader, code string) {
	t.Helper()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}

		if !strings.HasPrefix(line, code) {
			t.Fatalf("response %q does not start with %s", line, code)
		}

		if len(line) >= 4 && line[3] == ' ' {
			return
		}
	}
}

func TestListedOnlyRejections(t *testing.T) {
	srv, _, _ := testServer(t, "listed_only")

	tests := []struct {
		recipient string
		want      string
	}{
		{"noreply@example.com", "550 5.1.1 Contact support@example.com"},
		{"updates@example.com", "550 5.1.1 This address does not accept replies"},
		{"unknown@example.com", "550 5.1.1 Recipient does not exist"},
		{"unknown@elsewhere.example", "550 5.7.1 Relaying denied"},
	}

	for _, test := range tests {
		if got := smtpCommand(t, srv, test.recipient); got != test.want {
			t.Errorf("%s: got %q want %q", test.recipient, got, test.want)
		}
	}
}

func TestAllModeUsesDefaultForUnknownRecipient(t *testing.T) {
	srv, _, _ := testServer(t, "all")

	if got := smtpCommand(t, srv, "unknown@example.com"); got != "550 5.1.1 This address does not accept replies" {
		t.Fatalf("got %q", got)
	}
}

func TestRecipientRejectionsAreLogged(t *testing.T) {
	cfg := config.Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.ReplyRejection.Enabled = true
	cfg.ReplyRejection.UnknownRecipients = "listed_only"
	cfg.ReplyRejection.Domains = []string{"example.com"}
	cfg.ReplyRejection.DefaultMessage = "This address does not accept replies"
	cfg.ReplyRejection.Recipients = []config.ReplyRejectionRecipient{{Address: "noreply@example.com"}}

	log := new(captureLogger)

	s := &session{server: New(cfg, log), remoteIP: "192.0.2.10"}

	err := s.Mail("sender@example.net", nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		recipient string
		reason    string
	}{
		{"invalid", "invalid recipient address"},
		{"user@elsewhere.example", "relaying denied"},
		{"noreply@example.com", "configured recipient"},
		{"unknown@example.com", "recipient does not exist"},
	}

	for _, test := range tests {
		err = s.Rcpt(test.recipient, nil)
		if err == nil {
			t.Fatalf("Rcpt(%q) succeeded", test.recipient)
		}
	}

	want := ""

	for _, test := range tests {
		want += fmt.Sprintf("Reply rejection from %q sender %q recipient %q: %s\n", "192.0.2.10", "sender@example.net", test.recipient, test.reason)
	}

	if got := log.String(); got != want {
		t.Fatalf("log:\n%s\nwant:\n%s", got, want)
	}

	s.Reset()

	err = s.Rcpt("unknown@example.com", nil)
	if err == nil {
		t.Fatal("Rcpt after reset succeeded")
	}

	if got := log.String(); !strings.HasSuffix(got, "sender \"\" recipient \"unknown@example.com\": recipient does not exist\n") {
		t.Fatalf("reset did not clear sender in log: %s", got)
	}
}

func TestAllModeRejectionIsLogged(t *testing.T) {
	cfg := config.Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.ReplyRejection.Enabled = true
	cfg.ReplyRejection.UnknownRecipients = "all"
	cfg.ReplyRejection.Domains = []string{"example.com"}
	cfg.ReplyRejection.DefaultMessage = "This address does not accept replies"

	log := new(captureLogger)

	s := &session{server: New(cfg, log), remoteIP: "192.0.2.10"}

	err := s.Rcpt("unknown@example.com", nil)
	if err == nil {
		t.Fatal("Rcpt succeeded")
	}

	if got := log.String(); !strings.Contains(got, "recipient \"unknown@example.com\": default rejection\n") {
		t.Fatalf("log=%q", got)
	}
}

func TestDataIsNeverReachable(t *testing.T) {
	srv, _, _ := testServer(t, "all")

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	reader := bufio.NewReader(conn)

	readResponse(t, reader, "220")

	for _, command := range []string{
		"EHLO sender.example\r\n",
		"MAIL FROM:<sender@example.net>\r\n",
		"RCPT TO:<anything@example.com>\r\n",
		"DATA\r\n",
		"BDAT 0 LAST\r\n",
	} {
		fmt.Fprint(conn, command)

		response, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}

		if (strings.HasPrefix(command, "DATA") || strings.HasPrefix(command, "BDAT")) && (strings.HasPrefix(response, "354 ") || strings.HasPrefix(response, "250 2.0.0")) {
			t.Fatalf("%q accepted message data: %q", strings.TrimSpace(command), strings.TrimSpace(response))
		}
	}
}

func TestRejectionProtocolHasNoDeliveryCapabilities(t *testing.T) {
	srv, _, _ := testServer(t, "all")

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	reader := bufio.NewReader(conn)

	readResponse(t, reader, "220")

	fmt.Fprint(conn, "EHLO sender.example\r\n")

	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}

	if response != "250 2.0.0 Hello sender.example\r\n" {
		t.Fatalf("unexpected EHLO response %q", response)
	}

	fmt.Fprint(conn, "VRFY anything@example.com\r\n")

	response, err = reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(response, "500 ") || strings.Contains(response, "accept message") {
		t.Fatalf("misleading VRFY response %q", response)
	}
}

func TestRejectedRecipientsAreBoundedPerConnection(t *testing.T) {
	srv, _, _ := testServer(t, "all")

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)

	readResponse(t, reader, "220")

	fmt.Fprint(conn, "EHLO sender.example\r\n")
	readResponse(t, reader, "250")

	fmt.Fprint(conn, "MAIL FROM:<sender@example.net>\r\n")
	readResponse(t, reader, "250")

	for i := 0; i < maxCommandsPerConnection-2; i++ {
		fmt.Fprint(conn, "RCPT TO:<anything@example.com>\r\n")
		readResponse(t, reader, "550")
	}

	fmt.Fprint(conn, "RCPT TO:<anything@example.com>\r\n")
	readResponse(t, reader, "221")

	_, err = fmt.Fprint(conn, "NOOP\r\n")
	if err == nil {
		_, err = reader.ReadString('\n')
	}

	if err == nil {
		t.Fatal("connection remained open after rejected-recipient limit")
	}
}

func TestOverlongCommandClosesConnection(t *testing.T) {
	srv, _, _ := testServer(t, "all")

	conn, err := net.DialTimeout("tcp", srv.listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	reader := bufio.NewReader(conn)

	readResponse(t, reader, "220")

	fmt.Fprintf(conn, "NOOP %s\r\n", strings.Repeat("x", 8192))
	readResponse(t, reader, "221")

	_, err = reader.ReadString('\n')
	if err == nil {
		t.Fatal("connection remained open after an overlong command")
	}
}

func TestImmediateCancellationStops(t *testing.T) {
	cfg := config.Default()

	cfg.Server.Hostname = "mail.example.com"
	cfg.ReplyRejection.Enabled = true
	cfg.ReplyRejection.ListenAddr = "127.0.0.1:0"
	cfg.ReplyRejection.Domains = []string{"example.com"}

	err := cfg.Validate()
	if err != nil {
		t.Fatal(err)
	}

	srv := New(cfg, testLogger{})

	err = srv.Listen()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)

	go func() {
		done <- srv.Run(ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after immediate cancellation")
	}
}

func TestDisabledConfigurationDoesNotListen(t *testing.T) {
	cfg := config.Default()

	if cfg.ReplyRejection.Enabled {
		t.Fatal("reply rejection enabled by default")
	}

	// serve constructs and binds this component only when Enabled is true.
	srv := New(cfg, testLogger{})

	if srv.listener != nil {
		t.Fatal("New bound a listener")
	}
}
