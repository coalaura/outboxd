package smtpd

import (
	"context"
	"net"
	"os"
	"path/filepath"
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
	return cfg, k, spool
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
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
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
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
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
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
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
	done := make(chan error, 1)
	go func() { done <- srv.Run(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	_ = srv.starttlsListener.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("both listeners did not exit together")
	}
}

func TestGracefulShutdownTimeoutPath(t *testing.T) {
	prev := shutdownTimeout
	shutdownTimeout = 50 * time.Millisecond
	t.Cleanup(func() { shutdownTimeout = prev })

	cfg, k, spool := testServerParts(t)
	srv := New(cfg, k, nil, spool, testLog{})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	var hook atomic.Int32
	srv.shutdownHook = func() { hook.Add(1) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout path hang")
	}
	if hook.Load() == 0 {
		t.Fatal("shutdownHook not called")
	}
}

func TestNoLeakedWaiterOnListenerFail(t *testing.T) {
	cfg, k, spool := testServerParts(t)
	srv := New(cfg, k, nil, spool, testLog{})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	time.Sleep(40 * time.Millisecond)
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

func TestAuthLimiterConcurrentReserve(t *testing.T) {
	l := newAuthLimiter()
	const n = 50
	var wg sync.WaitGroup
	var okCount atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.reserve("10.0.0.1", "alice") {
				okCount.Add(1)
				time.Sleep(time.Millisecond)
				l.succeeded("10.0.0.1", "alice")
			}
		}()
	}
	wg.Wait()
	if okCount.Load() != n {
		t.Fatalf("ok=%d want %d", okCount.Load(), n)
	}

	for i := 0; i < freeAttempts+1; i++ {
		if !l.reserve("10.0.0.2", "bob") {
			t.Fatalf("reserve failed early at %d", i)
		}
		l.failed("10.0.0.2", "bob")
	}
	if l.reserve("10.0.0.2", "bob") {
		t.Fatal("should be locked out")
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
