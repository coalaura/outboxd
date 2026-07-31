package smtpd

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/certs"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
)

type testLog struct{}

func (testLog) Printf(string, ...any) {}
func (testLog) Println(...any)        {}

func testServerParts(t *testing.T) (*config.Config, *certs.Keeper, *queue.Queue) {
	t.Helper()
	base := t.TempDir()
	cfgPath := filepath.Join(base, "config.yml")
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	body := "server:\n  hostname: mail.test.example\n  domain: test.example\n  data_directory: " +
		filepath.ToSlash(dataDir) + "\n  max_message_bytes: 1048576\n  max_recipients: 10\n" +
		"  max_messages_per_hour: 100\n  max_recipients_per_hour: 1000\n  read_timeout: 1m\n  write_timeout: 1m\n" +
		"  submission_addr: \"127.0.0.1:0\"\n  implicit_tls_addr: \"127.0.0.1:0\"\n" +
		"  max_connections: 16\n  max_connections_per_ip: 4\n  auth_workers: 2\n  auth_queue: 8\n" +
		"tls:\n  mode: self_signed\n  certificate_file: tls/server.crt\n  private_key_file: tls/server.key\n  minimum_version: \"1.2\"\n" +
		"dkim:\n  selector: mail\n  private_key_file: dkim/mail.key\n  headers:\n    - From\n    - To\n    - Subject\n    - Date\n    - Message-ID\n" +
		"delivery:\n  tls_mode: opportunistic\n  max_attempts: 3\n  maximum_lifetime: 1h\n  initial_retry_delay: 1s\n  maximum_retry_delay: 1m\n" +
		"  domain_concurrency: 1\n  global_concurrency: 2\n  connection_timeout: 5s\n  command_timeout: 30s\n  submission_timeout: 1m\n" +
		"dns:\n  dmarc_policy: none\n  output_file: dns-records.txt\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	k, _, err := certs.Ensure(cfg)
	if err != nil {
		t.Fatalf("certs.Ensure: %v", err)
	}
	spool, err := queue.OpenDefault(filepath.Join(dataDir, "queue"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	return cfg, k, spool
}

func waitServeEntered(t *testing.T, srv *Server) <-chan struct{} {
	t.Helper()
	ch := make(chan struct{})
	var once sync.Once
	srv.serveEntered = func() {
		once.Do(func() { close(ch) })
	}
	return ch
}

func awaitCh(t *testing.T, ch <-chan struct{}, timeout time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for %s", what)
	}
}

func TestRunParentCancel(t *testing.T) {
	cfg, k, spool := testServerParts(t)
	srv := New(cfg, k, nil, spool, testLog{})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	if srv.starttls.Addr == "127.0.0.1:0" {
		t.Fatal("Listen did not update starttls.Addr from :0")
	}
	entered := waitServeEntered(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	awaitCh(t, entered, 3*time.Second, "serve entered")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after parent cancel")
	}
}

func TestRunSTARTTLSListenerFailure(t *testing.T) {
	cfg, k, spool := testServerParts(t)
	cfg.Server.DisableImplicitTLS = true
	cfg.Server.ImplicitTLSAddr = ""
	srv := New(cfg, k, nil, spool, testLog{})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	entered := waitServeEntered(t, srv)
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	awaitCh(t, entered, 3*time.Second, "serve entered")
	_ = srv.starttlsListener.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after starttls listener close")
	}
}

func TestRunImplicitTLSListenerFailure(t *testing.T) {
	cfg, k, spool := testServerParts(t)
	cfg.Server.DisableSubmission = true
	cfg.Server.SubmissionAddr = ""
	srv := New(cfg, k, nil, spool, testLog{})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	if srv.implicit.TLSConfig == nil {
		t.Fatal("missing TLS config")
	}
	entered := waitServeEntered(t, srv)
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	awaitCh(t, entered, 3*time.Second, "serve entered")
	_ = srv.implicitListener.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after implicit listener close")
	}
}

func TestRunBothExitTogether(t *testing.T) {
	cfg, k, spool := testServerParts(t)
	srv := New(cfg, k, nil, spool, testLog{})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	entered := waitServeEntered(t, srv)
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	awaitCh(t, entered, 3*time.Second, "serve entered")
	_ = srv.starttlsListener.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("both listeners did not exit together")
	}
}

func TestGracefulShutdownTimeoutPath(t *testing.T) {
	cfg, k, spool := testServerParts(t)
	cfg.Server.DisableImplicitTLS = true
	cfg.Server.ImplicitTLSAddr = ""
	srv := New(cfg, k, nil, spool, testLog{})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}

	// Inject a shutdown context that is already past its deadline once the session is held,
	// so Shutdown must take the deadline path and surface deadline exceeded.
	arm := make(chan struct{})
	var armed atomic.Bool
	srv.shutdownContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		select {
		case <-arm:
		case <-parent.Done():
			return context.WithCancel(parent)
		}
		armed.Store(true)
		return context.WithDeadline(parent, time.Now().Add(-time.Millisecond))
	}

	var hook atomic.Int32
	srv.shutdownHook = func() { hook.Add(1) }
	entered := waitServeEntered(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	awaitCh(t, entered, 3*time.Second, "serve entered")

	// Hold an active session open so Shutdown must wait and hit the deadline.
	conn, err := net.DialTimeout("tcp", srv.starttls.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	close(arm)
	cancel()
	var runErr error
	select {
	case runErr = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout path hang")
	}
	if hook.Load() != 1 {
		t.Fatalf("shutdownHook calls=%d want 1", hook.Load())
	}
	if !armed.Load() {
		t.Fatal("shutdown context factory was not used")
	}
	if runErr == nil {
		t.Fatal("Run must return deadline/timeout error; got nil")
	}
	low := strings.ToLower(runErr.Error())
	if !errors.Is(runErr, context.DeadlineExceeded) &&
		!strings.Contains(low, "deadline") && !strings.Contains(low, "timeout") {
		t.Fatalf("expected deadline/timeout in error, got %v", runErr)
	}
	_ = conn.Close()
}

func TestNoLeakedWaiterOnListenerFail(t *testing.T) {
	cfg, k, spool := testServerParts(t)
	srv := New(cfg, k, nil, spool, testLog{})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	entered := waitServeEntered(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	awaitCh(t, entered, 3*time.Second, "serve entered")
	_ = srv.starttlsListener.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run leaked waiter on parent ctx after listener fail")
	}
}

func TestConnectionLimitSaturation(t *testing.T) {
	lim := newConnectionLimiter(2, 2)
	if !lim.acquire("1.2.3.4") {
		t.Fatal("first")
	}
	if !lim.acquire("1.2.3.4") {
		t.Fatal("second")
	}
	if lim.acquire("1.2.3.4") {
		t.Fatal("third should fail global or per-ip")
	}
	lim.release("1.2.3.4")
	if !lim.acquire("1.2.3.4") {
		t.Fatal("after release")
	}
}

func TestListenUpdatesBoundAddr(t *testing.T) {
	cfg, k, spool := testServerParts(t)
	srv := New(cfg, k, nil, spool, testLog{})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if srv.starttlsListener != nil {
			_ = srv.starttlsListener.Close()
		}
		if srv.implicitListener != nil {
			_ = srv.implicitListener.Close()
		}
	})
	host, port, err := net.SplitHostPort(srv.starttls.Addr)
	if err != nil || port == "0" || host == "" {
		t.Fatalf("bad starttls addr %q err=%v", srv.starttls.Addr, err)
	}
	c, err := net.DialTimeout("tcp", srv.starttls.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}
