package deliver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/deliver"
	"github.com/coalaura/outboxd/internal/queue"
)

type memLog struct{}

func (memLog) Printf(string, ...any) {}
func (memLog) Println(...any)        {}

type recordingLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLog) Printf(format string, values ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, values...))
	l.mu.Unlock()
}

func (l *recordingLog) Println(values ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintln(values...))
	l.mu.Unlock()
}

func (l *recordingLog) contains(value string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Contains(strings.Join(l.lines, ""), value)
}

type fakeResolver struct {
	mx  map[string][]*net.MX
	ips map[string][]net.IP
}

func (f *fakeResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	mx, ok := f.mx[name]
	if ok {
		out := make([]*net.MX, len(mx))
		copy(out, mx)
		return out, nil
	}

	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]net.IP, error) {
	ips, ok := f.ips[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	out := make([]net.IP, 0, len(ips))

	for _, ip := range ips {
		if network == "ip4" && ip.To4() == nil {
			continue
		}

		if network == "ip6" && ip.To4() != nil {
			continue
		}

		out = append(out, append(net.IP(nil), ip...))
	}

	return out, nil
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func testConfig() *config.Config {
	allow := true
	return &config.Config{
		Server: config.Server{
			Hostname: "outboxd.test",
			Domain:   "outboxd.test",
		},
		Delivery: config.Delivery{
			TLSMode:                  "opportunistic",
			AllowPlaintext:           &allow,
			MaxAttempts:              3,
			MaximumLifetime:          "1h",
			InitialRetryDelay:        "1ms",
			MaximumRetryDelay:        "10ms",
			DomainConcurrency:        1,
			GlobalConcurrency:        2,
			ConnectionTimeout:        "5s",
			CommandTimeout:           "5s",
			SubmissionTimeout:        "5s",
			RequireValidMXTLSCert:    false,
			AllowPrivateDestinations: true,
		},
	}
}

func openQueue(t *testing.T) *queue.Queue {
	t.Helper()
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	return q
}

func addMsg(t *testing.T, q *queue.Queue, id, domain, rcpt string) {
	t.Helper()
	now := time.Now()
	env := &queue.Envelope{
		ID:       id,
		Username: "user",
		Sender:   "sender@example.com",
		Recipients: []queue.Recipient{{
			Address: rcpt,
			Domain:  domain,
			Status:  queue.StatusPending,
		}},
		Created:     now,
		NextAttempt: now,
	}
	body := []byte("From: sender@example.com\r\nTo: " + rcpt + "\r\nSubject: t\r\n\r\nHi\r\n")
	err := q.Add(env, body)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStoragePressureIsNonfatalAndBackedOff(t *testing.T) {
	root := t.TempDir()
	q, err := queue.Open(root, queue.Limits{MinFreeDisk: 1})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	addMsg(t, q, "storage-pressure", "missing.invalid", "user@missing.invalid")
	q.FreeDisk = func(string) (int64, error) { return 0, nil }

	logger := new(recordingLog)
	d := deliver.New(testConfig(), q, logger)
	d.SetResolver(&fakeResolver{mx: map[string][]*net.MX{}, ips: map[string][]net.IP{}})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err = d.Run(ctx)
	if err != nil {
		t.Fatalf("Run returned storage pressure as fatal: %v", err)
	}

	if !logger.contains("storage pressure") {
		t.Fatalf("storage pressure was not logged")
	}

	if q.Len() != 1 {
		t.Fatalf("queued messages=%d want 1 recoverable message", q.Len())
	}
}

func selfSigned(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

// legacyListener wraps a simple SMTP listener with a DATA-accepted channel.
type legacyListener struct {
	addr     string
	accepted chan struct{}
	once     sync.Once
}

func smtpListener(t *testing.T, startTLS bool, cert tls.Certificate) *legacyListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	l := &legacyListener{
		addr:     ln.Addr().String(),
		accepted: make(chan struct{}),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			go serveSMTP(c, startTLS, cert, l)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return l
}

func serveSMTP(c net.Conn, startTLS bool, cert tls.Certificate, l *legacyListener) {
	defer c.Close()
	rw := c
	write := func(s string) { _, _ = io.WriteString(rw, s) }
	buf := make([]byte, 1)
	readLine := func() string {
		var b strings.Builder

		for {
			n, err := rw.Read(buf)
			if n > 0 {
				b.WriteByte(buf[0])

				if buf[0] == '\n' {
					break
				}
			}

			if err != nil {
				return b.String()
			}
		}

		return b.String()
	}
	write("220 test ESMTP\r\n")
	secured := false

	for {
		line := readLine()
		if line == "" {
			return
		}

		upper := strings.ToUpper(strings.TrimSpace(line))

		switch {
		case strings.HasPrefix(upper, "EHLO"):
			write("250-localhost\r\n")

			if startTLS && !secured {
				write("250-STARTTLS\r\n")
			}

			write("250-8BITMIME\r\n")
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "STARTTLS"):
			if !startTLS || secured {
				write("503 bad\r\n")
				continue
			}

			write("220 ready\r\n")
			tlsConn := tls.Server(rw, &tls.Config{Certificates: []tls.Certificate{cert}})
			err := tlsConn.Handshake()
			if err != nil {
				return
			}

			rw = tlsConn
			secured = true
		case strings.HasPrefix(upper, "MAIL FROM:"):
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "RCPT TO:"):
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "DATA"):
			write("354 go\r\n")

			for {
				l2 := readLine()
				if strings.TrimRight(l2, "\r\n") == "." {
					break
				}
			}

			write("250 queued\r\n")
			l.once.Do(func() { close(l.accepted) })
		case strings.HasPrefix(upper, "QUIT"):
			write("221 bye\r\n")
			return
		default:
			write("250 OK\r\n")
		}
	}
}

func awaitAccepted(t *testing.T, l *legacyListener, timeout time.Duration) {
	t.Helper()

	select {
	case <-l.accepted:
	case <-time.After(timeout):
		t.Fatal("timeout waiting for DATA accepted")
	}
}

func TestDeliveryOpportunisticTLS(t *testing.T) {
	cert := selfSigned(t, "mx.example.com")
	ln := smtpListener(t, true, cert)

	q := openQueue(t)
	cfg := testConfig()
	cfg.Delivery.TLSMode = "opportunistic"
	d := deliver.New(cfg, q, memLog{})
	d.SetResolver(&fakeResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.example.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.example.com": {net.ParseIP("127.0.0.1")}},
	})
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", ln.addr)
	}))

	addMsg(t, q, "msg1", "ex.com", "a@ex.com")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	awaitAccepted(t, ln, 3*time.Second)
	cancel()
	<-done
}

func TestDeliveryRequiredRejectsPlain(t *testing.T) {
	cert := selfSigned(t, "mx.example.com")
	ln := smtpListener(t, false, cert)

	q := openQueue(t)
	cfg := testConfig()
	cfg.Delivery.TLSMode = "required"
	cfg.Delivery.MaxAttempts = 1
	allow := false
	cfg.Delivery.AllowPlaintext = &allow
	d := deliver.New(cfg, q, memLog{})
	d.SetResolver(&fakeResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.example.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.example.com": {net.ParseIP("127.0.0.1")}},
	})
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", ln.addr)
	}))

	addMsg(t, q, "msg2", "ex.com", "a@ex.com")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = d.Run(ctx)

	select {
	case <-ln.accepted:
		t.Fatal("required TLS must not deliver over plaintext")
	default:
	}

	ids, err := q.DeadIDs()
	if err != nil {
		t.Fatal(err)
	}

	if len(ids) == 0 {
		t.Fatal("expected message buried after required-TLS failure")
	}
}

func TestDeliveryPlaintextOpportunistic(t *testing.T) {
	cert := selfSigned(t, "mx.example.com")
	ln := smtpListener(t, false, cert)

	q := openQueue(t)
	cfg := testConfig()
	cfg.Delivery.TLSMode = "opportunistic"
	d := deliver.New(cfg, q, memLog{})
	d.SetResolver(&fakeResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.example.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.example.com": {net.ParseIP("127.0.0.1")}},
	})
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", ln.addr)
	}))

	addMsg(t, q, "msg3", "ex.com", "a@ex.com")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	awaitAccepted(t, ln, 3*time.Second)
	cancel()
	<-done
}

func TestPrivateIPRejection(t *testing.T) {
	q := openQueue(t)
	cfg := testConfig()
	cfg.Delivery.AllowPrivateDestinations = false
	cfg.Delivery.MaxAttempts = 1
	d := deliver.New(cfg, q, memLog{})
	d.SetResolver(&fakeResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.example.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.example.com": {net.ParseIP("10.0.0.5")}},
	})
	dialed := make(chan struct{}, 1)
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case dialed <- struct{}{}:
		default:
		}

		return nil, net.ErrClosed
	}))

	addMsg(t, q, "msg4", "ex.com", "a@ex.com")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = d.Run(ctx)

	select {
	case <-dialed:
		t.Fatal("must not dial private destination")
	default:
	}
}

func TestPrivateAllowlist(t *testing.T) {
	cert := selfSigned(t, "mx.example.com")
	ln := smtpListener(t, false, cert)

	q := openQueue(t)
	cfg := testConfig()
	cfg.Delivery.AllowPrivateDestinations = false
	cfg.Delivery.DestinationAllowlist = []string{"127.0.0.1"}
	d := deliver.New(cfg, q, memLog{})
	d.SetResolver(&fakeResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.example.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.example.com": {net.ParseIP("127.0.0.1")}},
	})
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", ln.addr)
	}))

	addMsg(t, q, "msg5", "ex.com", "a@ex.com")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	awaitAccepted(t, ln, 3*time.Second)
	cancel()
	<-done
}

func TestFairnessBlockedDomain(t *testing.T) {
	cert := selfSigned(t, "mx.fast.com")
	fast := smtpListener(t, false, cert)

	q := openQueue(t)
	cfg := testConfig()
	cfg.Delivery.DomainConcurrency = 1
	cfg.Delivery.GlobalConcurrency = 2
	d := deliver.New(cfg, q, memLog{})

	blockedIP := net.ParseIP("10.255.0.1")
	fastIP := net.ParseIP("10.255.0.2")
	blockedDialing := make(chan struct{}, 1)
	releaseBlocked := make(chan struct{})

	d.SetResolver(&fakeResolver{
		mx: map[string][]*net.MX{
			"blocked.com": {{Host: "mx.blocked.com.", Pref: 10}},
			"fast.com":    {{Host: "mx.fast.com.", Pref: 10}},
		},
		ips: map[string][]net.IP{
			"mx.blocked.com": {blockedIP},
			"mx.fast.com":    {fastIP},
		},
	})
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if ip != nil && ip.Equal(blockedIP) {
			select {
			case blockedDialing <- struct{}{}:
			default:
			}

			select {
			case <-releaseBlocked:
				return nil, context.Canceled
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", fast.addr)
	}))

	addMsg(t, q, "blk1", "blocked.com", "a@blocked.com")
	addMsg(t, q, "blk2", "blocked.com", "b@blocked.com")
	addMsg(t, q, "fst1", "fast.com", "c@fast.com")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	select {
	case <-blockedDialing:
	case <-time.After(3 * time.Second):
		cancel()
		<-done
		t.Fatal("blocked domain never dialed")
	}

	awaitAccepted(t, fast, 3*time.Second)
	close(releaseBlocked)
	cancel()
	<-done
}

func TestRunCancelUnblocksBlockedDial(t *testing.T) {
	// Regression: defer wg.Wait before cancel hung Run until attempt timeouts.
	q := openQueue(t)
	cfg := testConfig()
	cfg.Delivery.MaxAttempts = 5
	cfg.Delivery.SubmissionTimeout = "30s"
	cfg.Delivery.ConnectionTimeout = "30s"
	d := deliver.New(cfg, q, memLog{})
	started := make(chan struct{})
	var once sync.Once
	d.SetResolver(&fakeResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.ex.com": {net.ParseIP("127.0.0.1")}},
	})
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	addMsg(t, q, "hang1", "ex.com", "r@ex.com")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("dial never started")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run hung after cancel; defer order likely wrong")
	}
}

func TestRunDSNAtFullQueueNotFatal(t *testing.T) {
	// A DSN enqueued while the origin still occupies MaxMessages must not kill Run.
	root := t.TempDir()
	q, err := queue.Open(root, queue.Limits{MaxMessages: 1})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })

	cfg := testConfig()
	cfg.Delivery.MaxAttempts = 1
	cfg.Delivery.AllowPrivateDestinations = false
	cfg.Delivery.InitialRetryDelay = "1ms"
	cfg.Delivery.MaximumRetryDelay = "1ms"
	d := deliver.New(cfg, q, memLog{})

	// Hang the DSN recipient domain so Run cannot Finish the DSN before we assert.
	dsnHold := make(chan struct{})
	t.Cleanup(func() { close(dsnHold) })
	d.SetResolver(&hangResolver{
		fakeResolver: fakeResolver{
			mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com.", Pref: 10}}},
			ips: map[string][]net.IP{"mx.ex.com": {net.ParseIP("10.0.0.1")}},
		},
		hangDomain: "example.com",
		hold:       dsnHold,
	})
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("should not dial private")}
	}))

	now := time.Now()
	env := &queue.Envelope{
		ID: "full1", Username: "user", Sender: "sender@example.com",
		Recipients: []queue.Recipient{{
			Address: "r@ex.com", Domain: "ex.com", Status: queue.StatusPending,
		}},
		Created: now, NextAttempt: now,
	}
	body := []byte("From: sender@example.com\r\nTo: r@ex.com\r\nSubject: t\r\n\r\nHi\r\n")
	err = q.Add(env, body)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	deadline := time.After(3 * time.Second)

	for {
		select {
		case err := <-done:
			t.Fatalf("Run returned early: %v", err)
		case <-deadline:
			cancel()

			err = <-done
			if err != nil {
				t.Fatalf("Run fatal after deadline: %v", err)
			}

			t.Fatal("message never buried")
		default:
			_, deadErr := os.Stat(filepath.Join(root, "dead", "full1"))
			_, dsnErr := os.Stat(filepath.Join(root, "ready", queue.DSNID("full1", env.Incarnation, 0)))
			if deadErr == nil && dsnErr == nil {
				goto buried
			}

			runtime.Gosched()
		}
	}

buried:
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after bury returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}

// hangResolver is fakeResolver but LookupMX blocks on hangDomain until hold is closed or ctx ends.
type hangResolver struct {
	fakeResolver
	hangDomain string
	hold       <-chan struct{}
}

func (h *hangResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if name == h.hangDomain {
		select {
		case <-h.hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return h.fakeResolver.LookupMX(ctx, name)
}
