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
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/deliver"
	"github.com/coalaura/outboxd/internal/queue"
)

type memLog struct{}

func (memLog) Printf(string, ...any) {}
func (memLog) Println(...any)        {}

type fakeResolver struct {
	mx  map[string][]*net.MX
	ips map[string][]net.IP
}

func (f *fakeResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if mx, ok := f.mx[name]; ok {
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
	if err := q.Add(env, body); err != nil {
		t.Fatal(err)
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

func smtpListener(t *testing.T, startTLS bool, cert tls.Certificate, accepted *atomic.Int64) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSMTP(c, startTLS, cert, accepted)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func serveSMTP(c net.Conn, startTLS bool, cert tls.Certificate, accepted *atomic.Int64) {
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
			if err := tlsConn.Handshake(); err != nil {
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
				l := readLine()
				if strings.TrimRight(l, "\r\n") == "." {
					break
				}
			}
			write("250 queued\r\n")
			if accepted != nil {
				accepted.Add(1)
			}
		case strings.HasPrefix(upper, "QUIT"):
			write("221 bye\r\n")
			return
		default:
			write("250 OK\r\n")
		}
	}
}

func waitAccepted(t *testing.T, n *atomic.Int64, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n.Load() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("accepted=%d want>=%d", n.Load(), want)
}

func TestDeliveryOpportunisticTLS(t *testing.T) {
	var accepted atomic.Int64
	cert := selfSigned(t, "mx.example.com")
	addr := smtpListener(t, true, cert, &accepted)

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
		return nd.DialContext(ctx, "tcp", addr)
	}))

	addMsg(t, q, "msg1", "ex.com", "a@ex.com")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	waitAccepted(t, &accepted, 1, 3*time.Second)
	cancel()
	<-done
}

func TestDeliveryRequiredRejectsPlain(t *testing.T) {
	var accepted atomic.Int64
	cert := selfSigned(t, "mx.example.com")
	addr := smtpListener(t, false, cert, &accepted)

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
		return nd.DialContext(ctx, "tcp", addr)
	}))

	addMsg(t, q, "msg2", "ex.com", "a@ex.com")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = d.Run(ctx)

	if accepted.Load() != 0 {
		t.Fatalf("required TLS must not deliver over plaintext, accepted=%d", accepted.Load())
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
	var accepted atomic.Int64
	cert := selfSigned(t, "mx.example.com")
	addr := smtpListener(t, false, cert, &accepted)

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
		return nd.DialContext(ctx, "tcp", addr)
	}))

	addMsg(t, q, "msg3", "ex.com", "a@ex.com")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	waitAccepted(t, &accepted, 1, 3*time.Second)
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
	var dialed atomic.Int64
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed.Add(1)
		return nil, net.ErrClosed
	}))

	addMsg(t, q, "msg4", "ex.com", "a@ex.com")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = d.Run(ctx)

	if dialed.Load() != 0 {
		t.Fatalf("must not dial private destination, dialed=%d", dialed.Load())
	}
}

func TestPrivateAllowlist(t *testing.T) {
	var accepted atomic.Int64
	cert := selfSigned(t, "mx.example.com")
	addr := smtpListener(t, false, cert, &accepted)

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
		return nd.DialContext(ctx, "tcp", addr)
	}))

	addMsg(t, q, "msg5", "ex.com", "a@ex.com")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	waitAccepted(t, &accepted, 1, 3*time.Second)
	cancel()
	<-done
}

func TestFairnessBlockedDomain(t *testing.T) {
	var fastAccepted atomic.Int64
	var blockedDialing atomic.Int64
	releaseBlocked := make(chan struct{})

	cert := selfSigned(t, "mx.fast.com")
	fastAddr := smtpListener(t, false, cert, &fastAccepted)

	q := openQueue(t)
	cfg := testConfig()
	cfg.Delivery.DomainConcurrency = 1
	cfg.Delivery.GlobalConcurrency = 2
	d := deliver.New(cfg, q, memLog{})

	blockedIP := net.ParseIP("10.255.0.1")
	fastIP := net.ParseIP("10.255.0.2")

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
			blockedDialing.Add(1)
			select {
			case <-releaseBlocked:
				return nil, context.Canceled
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", fastAddr)
	}))

	addMsg(t, q, "blk1", "blocked.com", "a@blocked.com")
	addMsg(t, q, "blk2", "blocked.com", "b@blocked.com")
	addMsg(t, q, "fst1", "fast.com", "c@fast.com")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && blockedDialing.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if blockedDialing.Load() == 0 {
		cancel()
		<-done
		t.Fatal("blocked domain never dialed")
	}

	waitAccepted(t, &fastAccepted, 1, 3*time.Second)
	close(releaseBlocked)
	cancel()
	<-done
}
