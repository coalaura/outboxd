package rejection

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
)

type testLogger struct{}

func (testLogger) Printf(string, ...any) {}

func (testLogger) Println(...any) {}

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

		if strings.HasPrefix(response, "354 ") || strings.HasPrefix(response, "250 2.0.0") {
			t.Fatalf("%q accepted message data: %q", strings.TrimSpace(command), strings.TrimSpace(response))
		}
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
