package deliver

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/queue"
)

type nopLogger struct{}

func (nopLogger) Printf(string, ...any) {}
func (nopLogger) Println(...any)        {}

type fixedResolver struct {
	mx  map[string][]*net.MX
	ips map[string][]net.IP
}

func (f *fixedResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	mx, ok := f.mx[name]
	if ok {
		out := make([]*net.MX, len(mx))
		copy(out, mx)
		return out, nil
	}

	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fixedResolver) LookupNetIP(ctx context.Context, network, host string) ([]net.IP, error) {
	ips, ok := f.ips[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	out := make([]net.IP, len(ips))
	copy(out, ips)
	return out, nil
}

type dialRec struct {
	mu    sync.Mutex
	order []string
	fn    func(ctx context.Context, network, address string) (net.Conn, error)
}

func (d *dialRec) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.order = append(d.order, address)
	d.mu.Unlock()
	return d.fn(ctx, network, address)
}

type mapDial struct {
	m map[string]string
}

func dialMap(m map[string]string) Dialer { return mapDial{m: m} }

func (m mapDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	target, ok := m.m[address]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("unmapped " + address)}
	}

	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", target)
}

func testDeliverCfg() *config.Config {
	allow := true
	return &config.Config{
		Server: config.Server{Hostname: "outboxd.test", Domain: "outboxd.test"},
		Delivery: config.Delivery{
			TLSMode:                  "opportunistic",
			AllowPlaintext:           &allow,
			MaxAttempts:              5,
			MaximumLifetime:          "1h",
			InitialRetryDelay:        "1ms",
			MaximumRetryDelay:        "5ms",
			DomainConcurrency:        2,
			GlobalConcurrency:        4,
			ConnectionTimeout:        "5s",
			CommandTimeout:           "5s",
			SubmissionTimeout:        "5s",
			RequireValidMXTLSCert:    true,
			AllowPrivateDestinations: true,
		},
	}
}

func mintTestCert(t *testing.T, cn string) (tls.Certificate, *x509.CertPool) {
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
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tlsCert, pool
}

func serveCapOnly(ln net.Listener, utf8, eight bool) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}

		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.WriteString(c, "220 mx\r\n")
			br := bufio.NewReader(c)

			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}

				upper := strings.ToUpper(strings.TrimRight(line, "\r\n"))

				switch {
				case strings.HasPrefix(upper, "EHLO"):
					resp := "250-mx\r\n"
					if eight {
						resp += "250-8BITMIME\r\n"
					}

					if utf8 {
						resp += "250-SMTPUTF8\r\n"
					}

					resp += "250 OK\r\n"
					_, _ = io.WriteString(c, resp)
				case strings.HasPrefix(upper, "QUIT"):
					_, _ = io.WriteString(c, "221 bye\r\n")
					return
				default:
					_, _ = io.WriteString(c, "250 OK\r\n")
				}
			}
		}(c)
	}
}

// startMiniMX is a minimal STARTTLS MX for package-internal tests.
func startMiniMX(t *testing.T, startTLS bool, cert tls.Certificate, utf8, eight bool) (addr string, dataDone <-chan struct{}, conns *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	var (
		closeDone sync.Once
		n         atomic.Int32
	)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			n.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				rw := net.Conn(c)
				br := bufio.NewReader(rw)
				_, _ = io.WriteString(rw, "220 mx\r\n")
				secured := false

				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}

					upper := strings.ToUpper(strings.TrimRight(line, "\r\n"))

					switch {
					case strings.HasPrefix(upper, "EHLO"):
						resp := "250-mx\r\n"
						if startTLS && !secured {
							resp += "250-STARTTLS\r\n"
						}

						if eight {
							resp += "250-8BITMIME\r\n"
						}

						if utf8 {
							resp += "250-SMTPUTF8\r\n"
						}

						resp += "250 OK\r\n"
						_, _ = io.WriteString(rw, resp)
					case strings.HasPrefix(upper, "STARTTLS"):
						_, _ = io.WriteString(rw, "220 ready\r\n")
						tc := tls.Server(rw, &tls.Config{Certificates: []tls.Certificate{cert}})
						err = tc.Handshake()
						if err != nil {
							return
						}

						rw = tc
						br = bufio.NewReader(rw)
						secured = true
					case strings.HasPrefix(upper, "MAIL FROM:"):
						_, _ = io.WriteString(rw, "250 OK\r\n")
					case strings.HasPrefix(upper, "RCPT TO:"):
						_, _ = io.WriteString(rw, "250 OK\r\n")
					case strings.HasPrefix(upper, "DATA"):
						_, _ = io.WriteString(rw, "354 go\r\n")

						for {
							l, err := br.ReadString('\n')
							if err != nil {
								return
							}

							if strings.TrimRight(l, "\r\n") == "." {
								break
							}
						}

						_, _ = io.WriteString(rw, "250 queued\r\n")
						closeDone.Do(func() { close(done) })
					case strings.HasPrefix(upper, "QUIT"):
						_, _ = io.WriteString(rw, "221 bye\r\n")
						return
					default:
						_, _ = io.WriteString(rw, "250 OK\r\n")
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), done, &n
}

func TestCandidateIPFallbackOrder(t *testing.T) {
	cert, pool := mintTestCert(t, "mx.ex.com")
	mxAddr, dataDone, conns := startMiniMX(t, true, cert, false, true)
	ipBad := net.ParseIP("10.255.202.1")
	ipGood := net.ParseIP("10.255.202.2")

	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	d := New(cfg, q, nopLogger{})
	d.SetTLSRootCAs(pool)

	// Preserve resolver order: bad then good.
	d.orderIPs = func([]net.IP) {}
	d.SetResolver(&fixedResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.ex.com": {ipBad, ipGood}},
	})
	rec := &dialRec{fn: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if host == ipBad.String() {
			return nil, errors.New("network down")
		}

		if host != ipGood.String() {
			return nil, errors.New("unexpected " + host)
		}

		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", mxAddr)
	}}
	d.SetDialer(rec)

	now := time.Now()
	env := &queue.Envelope{
		ID: "ipord", Username: "u", Sender: "a@ex.com",
		Recipients:  []queue.Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: queue.StatusPending}},
		Created:     now,
		NextAttempt: now,
	}
	body := []byte("From: a@ex.com\r\nTo: b@ex.com\r\nSubject: t\r\n\r\nHi\r\n")
	err = q.Add(env, body)
	if err != nil {
		t.Fatal(err)
	}

	// Take from schedule so Add's NextAttempt ownership is correct, then deliver directly.
	got, err := q.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	err = d.domain(context.Background(), got, "ex.com", []int{0})
	if err != nil {
		t.Fatalf("domain: %v", err)
	}

	if got.Recipients[0].Status != queue.StatusSent {
		t.Fatalf("status=%s detail=%s", got.Recipients[0].Status, got.Recipients[0].Detail)
	}

	select {
	case <-dataDone:
	case <-time.After(3 * time.Second):
		t.Fatal("DATA timeout")
	}

	if conns.Load() != 1 {
		t.Fatalf("successful MX TCP conns=%d want 1", conns.Load())
	}

	rec.mu.Lock()
	order := append([]string(nil), rec.order...)
	rec.mu.Unlock()

	if len(order) != 2 {
		t.Fatalf("dial order len=%d want 2: %v", len(order), order)
	}

	if !strings.Contains(order[0], ipBad.String()) || !strings.Contains(order[1], ipGood.String()) {
		t.Fatalf("exact dial order want bad then good, got %v", order)
	}
}

func TestDomainCapabilityAllSMTPUTF8Missing(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ln1.Close() })
	go serveCapOnly(ln1, false, true)

	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	allow := true
	cfg.Delivery.AllowPlaintext = &allow
	cfg.Delivery.RequireValidMXTLSCert = false
	d := New(cfg, q, nopLogger{})
	ip := net.ParseIP("10.255.210.1")
	d.SetResolver(&fixedResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.ex.com": {ip}},
	})
	d.orderIPs = func([]net.IP) {}
	d.SetDialer(dialMap(map[string]string{net.JoinHostPort(ip.String(), "25"): ln1.Addr().String()}))

	now := time.Now()
	env := &queue.Envelope{
		ID: "cap1", Username: "u", Sender: "björn@ex.com",
		Recipients: []queue.Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: queue.StatusPending}},
		Created:    now, NextAttempt: now, SMTPUTF8: true,
	}
	err = d.domain(context.Background(), env, "ex.com", []int{0})
	if err != nil {
		t.Fatalf("domain err=%v", err)
	}

	if env.Recipients[0].Status != queue.StatusFailed {
		t.Fatalf("want failed permanent, got %s", env.Recipients[0].Status)
	}

	if !strings.Contains(env.Recipients[0].Detail, "SMTPUTF8") {
		t.Fatalf("detail=%q", env.Recipients[0].Detail)
	}
}

func TestDomainCapabilityAll8BitMissing(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ln1.Close() })
	go serveCapOnly(ln1, true, false)

	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	allow := true
	cfg.Delivery.AllowPlaintext = &allow
	cfg.Delivery.RequireValidMXTLSCert = false
	d := New(cfg, q, nopLogger{})
	ip := net.ParseIP("10.255.210.2")
	d.SetResolver(&fixedResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.ex.com": {ip}},
	})
	d.orderIPs = func([]net.IP) {}
	d.SetDialer(dialMap(map[string]string{net.JoinHostPort(ip.String(), "25"): ln1.Addr().String()}))

	now := time.Now()
	env := &queue.Envelope{
		ID: "cap8", Username: "u", Sender: "a@ex.com",
		Recipients: []queue.Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: queue.StatusPending}},
		Created:    now, NextAttempt: now, EightBit: true,
	}
	err = d.domain(context.Background(), env, "ex.com", []int{0})
	if err != nil {
		t.Fatalf("domain err=%v", err)
	}

	if env.Recipients[0].Status != queue.StatusFailed {
		t.Fatalf("want failed, got %s", env.Recipients[0].Status)
	}

	if !strings.Contains(env.Recipients[0].Detail, "8BITMIME") {
		t.Fatalf("detail=%q", env.Recipients[0].Detail)
	}
}

func TestDomainMixedCapabilitiesCombined(t *testing.T) {
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = lnA.Close() })
	go serveCapOnly(lnA, true, false)
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = lnB.Close() })
	go serveCapOnly(lnB, false, true)

	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	allow := true
	cfg.Delivery.AllowPlaintext = &allow
	cfg.Delivery.RequireValidMXTLSCert = false
	d := New(cfg, q, nopLogger{})
	ipA := net.ParseIP("10.255.211.1")
	ipB := net.ParseIP("10.255.211.2")
	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{"ex.com": {
			{Host: "a.ex.com.", Pref: 10},
			{Host: "b.ex.com.", Pref: 20},
		}},
		ips: map[string][]net.IP{
			"a.ex.com": {ipA},
			"b.ex.com": {ipB},
		},
	})
	d.orderIPs = func([]net.IP) {}
	d.SetDialer(dialMap(map[string]string{
		net.JoinHostPort(ipA.String(), "25"): lnA.Addr().String(),
		net.JoinHostPort(ipB.String(), "25"): lnB.Addr().String(),
	}))

	now := time.Now()
	env := &queue.Envelope{
		ID: "bothcap", Username: "u", Sender: "björn@ex.com",
		Recipients: []queue.Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: queue.StatusPending}},
		Created:    now, NextAttempt: now, SMTPUTF8: true, EightBit: true,
	}
	err = d.domain(context.Background(), env, "ex.com", []int{0})
	if err != nil {
		t.Fatalf("domain err=%v", err)
	}

	if env.Recipients[0].Status != queue.StatusFailed {
		t.Fatalf("status=%s", env.Recipients[0].Status)
	}

	det := env.Recipients[0].Detail
	if !strings.Contains(det, "SMTPUTF8") || !strings.Contains(det, "8BITMIME") {
		t.Fatalf("combined detail=%q", det)
	}
}

func TestDomainTempThenCapabilityKeepsPending(t *testing.T) {
	lnCap, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = lnCap.Close() })
	go serveCapOnly(lnCap, false, true)

	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	allow := true
	cfg.Delivery.AllowPlaintext = &allow
	cfg.Delivery.RequireValidMXTLSCert = false
	d := New(cfg, q, nopLogger{})
	ipNet := net.ParseIP("10.255.212.1")
	ipCap := net.ParseIP("10.255.212.2")
	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{"ex.com": {
			{Host: "net.ex.com.", Pref: 10},
			{Host: "cap.ex.com.", Pref: 20},
		}},
		ips: map[string][]net.IP{
			"net.ex.com": {ipNet},
			"cap.ex.com": {ipCap},
		},
	})
	d.orderIPs = func([]net.IP) {}
	d.SetDialer(dialMap(map[string]string{
		net.JoinHostPort(ipCap.String(), "25"): lnCap.Addr().String(),
	}))

	now := time.Now()
	env := &queue.Envelope{
		ID: "mix", Username: "u", Sender: "björn@ex.com",
		Recipients: []queue.Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: queue.StatusPending}},
		Created:    now, NextAttempt: now, SMTPUTF8: true,
	}
	err = d.domain(context.Background(), env, "ex.com", []int{0})
	if err == nil {
		t.Fatal("expected temporary error from mixed outcomes")
	}

	if env.Recipients[0].Status != queue.StatusPending {
		t.Fatalf("must remain pending, got %s detail=%s", env.Recipients[0].Status, env.Recipients[0].Detail)
	}

	if errors.Is(err, errSMTPUTF8Unsupported) || errors.Is(err, err8BITMIMEUnsupported) {
		t.Fatalf("must not return capability-only error, got %v", err)
	}
}

func TestDomainTempThenPrivateKeepsPending(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	cfg.Delivery.AllowPrivateDestinations = false
	allow := true
	cfg.Delivery.AllowPlaintext = &allow
	cfg.Delivery.RequireValidMXTLSCert = false
	d := New(cfg, q, nopLogger{})

	// First MX: publicly-routable IP, unmapped dialer → temporary; second: private.
	ipPub := net.ParseIP("8.8.8.8")
	ipPriv := net.ParseIP("10.255.100.2")
	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{"ex.com": {
			{Host: "net.ex.com.", Pref: 10},
			{Host: "priv.ex.com.", Pref: 20},
		}},
		ips: map[string][]net.IP{
			"net.ex.com":  {ipPub},
			"priv.ex.com": {ipPriv},
		},
	})
	d.orderIPs = func([]net.IP) {}
	d.SetDialer(dialMap(map[string]string{})) // unmapped → temp on public MX

	now := time.Now()
	env := &queue.Envelope{
		ID: "privmix", Username: "u", Sender: "a@ex.com",
		Recipients: []queue.Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: queue.StatusPending}},
		Created:    now, NextAttempt: now,
	}
	err = d.domain(context.Background(), env, "ex.com", []int{0})
	if err == nil {
		t.Fatal("expected temporary error when any candidate is retryable")
	}

	if env.Recipients[0].Status != queue.StatusPending {
		t.Fatalf("must remain pending, got %s detail=%s", env.Recipients[0].Status, env.Recipients[0].Detail)
	}

	if errors.Is(err, errPrivateDestination) {
		t.Fatalf("must not treat as permanent private-only error, got %v", err)
	}
}

func TestDomainPrivateThenTempKeepsPending(t *testing.T) {
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	cfg.Delivery.AllowPrivateDestinations = false
	allow := true
	cfg.Delivery.AllowPlaintext = &allow
	cfg.Delivery.RequireValidMXTLSCert = false
	d := New(cfg, q, nopLogger{})
	ipPriv := net.ParseIP("10.255.101.1")
	ipPub := net.ParseIP("1.1.1.1")
	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{"ex.com": {
			{Host: "priv.ex.com.", Pref: 10},
			{Host: "net.ex.com.", Pref: 20},
		}},
		ips: map[string][]net.IP{
			"priv.ex.com": {ipPriv},
			"net.ex.com":  {ipPub},
		},
	})
	d.orderIPs = func([]net.IP) {}
	d.SetDialer(dialMap(map[string]string{}))

	now := time.Now()
	env := &queue.Envelope{
		ID: "privmix2", Username: "u", Sender: "a@ex.com",
		Recipients: []queue.Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: queue.StatusPending}},
		Created:    now, NextAttempt: now,
	}
	err = d.domain(context.Background(), env, "ex.com", []int{0})
	if err == nil {
		t.Fatal("expected temporary error")
	}

	if env.Recipients[0].Status != queue.StatusPending {
		t.Fatalf("must remain pending, got %s", env.Recipients[0].Status)
	}

	if errors.Is(err, errPrivateDestination) {
		t.Fatalf("must not treat as permanent private-only error, got %v", err)
	}
}

func TestDomainCapabilityThenTempKeepsPending(t *testing.T) {
	lnCap, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = lnCap.Close() })
	go serveCapOnly(lnCap, false, true)

	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })
	cfg := testDeliverCfg()
	allow := true
	cfg.Delivery.AllowPlaintext = &allow
	cfg.Delivery.RequireValidMXTLSCert = false
	d := New(cfg, q, nopLogger{})
	ipCap := net.ParseIP("10.255.213.1")
	ipNet := net.ParseIP("10.255.213.2")

	// Capability first, temporary second (order reverse of prior test).
	d.SetResolver(&fixedResolver{
		mx: map[string][]*net.MX{"ex.com": {
			{Host: "cap.ex.com.", Pref: 10},
			{Host: "net.ex.com.", Pref: 20},
		}},
		ips: map[string][]net.IP{
			"cap.ex.com": {ipCap},
			"net.ex.com": {ipNet},
		},
	})
	d.orderIPs = func([]net.IP) {}
	d.SetDialer(dialMap(map[string]string{
		net.JoinHostPort(ipCap.String(), "25"): lnCap.Addr().String(),
	}))

	now := time.Now()
	env := &queue.Envelope{
		ID: "mix2", Username: "u", Sender: "björn@ex.com",
		Recipients: []queue.Recipient{{Address: "b@ex.com", Domain: "ex.com", Status: queue.StatusPending}},
		Created:    now, NextAttempt: now, SMTPUTF8: true,
	}
	err = d.domain(context.Background(), env, "ex.com", []int{0})
	if err == nil {
		t.Fatal("expected temporary error")
	}

	if env.Recipients[0].Status != queue.StatusPending {
		t.Fatalf("must remain pending, got %s", env.Recipients[0].Status)
	}
}

func TestRunQueueErrorCancelsAttemptsBeforeWait(t *testing.T) {
	// Queue Next error must cancel in-flight attempts before wg.Wait (defer order).
	q, err := queue.Open(t.TempDir(), queue.Limits{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = q.Close() })

	cfg := testDeliverCfg()
	cfg.Delivery.MaxAttempts = 5
	cfg.Delivery.ConnectionTimeout = "30s"
	cfg.Delivery.SubmissionTimeout = "30s"
	d := New(cfg, q, nopLogger{})

	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})
	var startOnce, cancelOnce sync.Once
	d.SetResolver(&fixedResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.ex.com": {net.ParseIP("127.0.0.1")}},
	})
	d.SetDialer(dialFn(func(ctx context.Context, network, address string) (net.Conn, error) {
		startOnce.Do(func() { close(dialStarted) })
		<-ctx.Done()
		cancelOnce.Do(func() { close(dialCanceled) })
		return nil, ctx.Err()
	}))

	now := time.Now()
	env := &queue.Envelope{
		ID: "hang-q", Username: "user", Sender: "sender@example.com",
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

	sentinel := errors.New("queue next failed")
	var calls atomic.Int32
	realNext := q.Next
	d.next = func(ctx context.Context) (*queue.Envelope, error) {
		if calls.Add(1) == 1 {
			return realNext(ctx)
		}

		<-dialStarted
		return nil, sentinel
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	select {
	case err := <-done:
		if !errors.Is(err, sentinel) {
			t.Fatalf("Run want sentinel, got %v", err)
		}

		select {
		case <-dialCanceled:
		default:
			t.Fatal("dialer did not observe cancel before Run returned")
		}
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("Run hung after queue error; cancel must run before wg.Wait")
	}
}

type dialFn func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialFn) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}
