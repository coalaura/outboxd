package deliver_test

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
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/deliver"
	"github.com/coalaura/outboxd/internal/queue"
)

// sessionLog records the SMTP conversation for one client connection.
type sessionLog struct {
	mu       sync.Mutex
	commands []string
	mailLine string
	data     bool
	tls      bool
	sni      string
}

func (s *sessionLog) add(cmd string) {
	s.mu.Lock()
	s.commands = append(s.commands, cmd)
	s.mu.Unlock()
}

// fakeMX is a deterministic MX, synchronized via readiness / event channels.
type fakeMX struct {
	ln       net.Listener
	ready    chan struct{}
	conns    atomic.Int64
	sessions []*sessionLog
	mu       sync.Mutex

	// dataDone is closed on first successful DATA (do not wait with sleeps).
	dataOnce sync.Once
	dataDone chan struct{}
	// sessionDone receives after each connection handler exits.
	sessionDone chan struct{}

	startTLS   bool
	extUTF8    bool
	ext8bit    bool
	cert       tls.Certificate
	brokenTLS  bool // handshake fails after 220
	startTLSEr bool // STARTTLS command returns 454
}

func startFakeMX(t *testing.T, mx *fakeMX) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mx.ln = ln
	mx.ready = make(chan struct{})
	mx.dataDone = make(chan struct{})
	mx.sessionDone = make(chan struct{}, 64)
	go mx.serve()
	close(mx.ready)
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func (mx *fakeMX) serve() {
	for {
		c, err := mx.ln.Accept()
		if err != nil {
			return
		}
		mx.conns.Add(1)
		log := &sessionLog{}
		mx.mu.Lock()
		mx.sessions = append(mx.sessions, log)
		mx.mu.Unlock()
		go func() {
			mx.handle(c, log)
			select {
			case mx.sessionDone <- struct{}{}:
			default:
			}
		}()
	}
}

func (mx *fakeMX) handle(c net.Conn, log *sessionLog) {
	defer c.Close()
	rw := c
	br := bufio.NewReader(rw)
	write := func(s string) { _, _ = io.WriteString(rw, s) }
	readLine := func() (string, error) {
		line, err := br.ReadString('\n')
		return line, err
	}

	write("220 mx.test ESMTP\r\n")
	secured := false
	for {
		line, err := readLine()
		if err != nil {
			return
		}
		raw := strings.TrimRight(line, "\r\n")
		log.add(raw)
		upper := strings.ToUpper(raw)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			write("250-mx.test\r\n")
			if mx.startTLS && !secured {
				write("250-STARTTLS\r\n")
			}
			if mx.ext8bit {
				write("250-8BITMIME\r\n")
			}
			if mx.extUTF8 {
				write("250-SMTPUTF8\r\n")
			}
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "STARTTLS"):
			if !mx.startTLS || secured {
				write("503 bad\r\n")
				continue
			}
			if mx.startTLSEr {
				write("454 TLS not available\r\n")
				continue
			}
			write("220 ready\r\n")
			cfg := &tls.Config{Certificates: []tls.Certificate{mx.cert}}
			tlsConn := tls.Server(rw, cfg)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			if mx.brokenTLS {
				_ = tlsConn.Close()
				return
			}
			cs := tlsConn.ConnectionState()
			log.sni = cs.ServerName
			log.tls = true
			rw = tlsConn
			br = bufio.NewReader(rw)
			secured = true
		case strings.HasPrefix(upper, "MAIL FROM:"):
			log.mailLine = raw
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "RCPT TO:"):
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "DATA"):
			log.data = true
			write("354 go\r\n")
			for {
				l, err := readLine()
				if err != nil {
					return
				}
				if strings.TrimRight(l, "\r\n") == "." {
					break
				}
			}
			write("250 queued\r\n")
			mx.dataOnce.Do(func() { close(mx.dataDone) })
		case strings.HasPrefix(upper, "QUIT"):
			write("221 bye\r\n")
			return
		default:
			write("250 OK\r\n")
		}
	}
}

func (mx *fakeMX) mailLines() []string {
	mx.mu.Lock()
	defer mx.mu.Unlock()
	var out []string
	for _, s := range mx.sessions {
		if s.mailLine != "" {
			out = append(out, s.mailLine)
		}
	}
	return out
}

func (mx *fakeMX) anyData() bool {
	mx.mu.Lock()
	defer mx.mu.Unlock()
	for _, s := range mx.sessions {
		if s.data {
			return true
		}
	}
	return false
}

func mintCert(t *testing.T, cn string) (tls.Certificate, *x509.CertPool, *x509.Certificate) {
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
	return tlsCert, pool, parsed
}

func deliverCfg() *config.Config {
	allow := true
	return &config.Config{
		Server: config.Server{Hostname: "outboxd.test", Domain: "outboxd.test"},
		Delivery: config.Delivery{
			TLSMode:                  "opportunistic",
			AllowPlaintext:           &allow,
			MaxAttempts:              3,
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

func wireMX(t *testing.T, d *deliver.Deliverer, domain, mxHost, addr string) {
	t.Helper()
	host, port, _ := net.SplitHostPort(addr)
	_ = port
	d.SetResolver(&fakeResolver{
		mx:  map[string][]*net.MX{domain: {{Host: mxHost + ".", Pref: 10}}},
		ips: map[string][]net.IP{mxHost: {net.ParseIP(host)}},
	})
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", addr)
	}))
}

func runDeliverer(t *testing.T, d *deliver.Deliverer) (cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- d.Run(ctx) }()
	return cancel, ch
}

func await(t *testing.T, ch <-chan struct{}, timeout time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for %s", what)
	}
}

func awaitSession(t *testing.T, mx *fakeMX, timeout time.Duration) {
	t.Helper()
	select {
	case <-mx.sessionDone:
	case <-time.After(timeout):
		t.Fatal("timeout waiting for MX session end")
	}
}

func addEnvelope(t *testing.T, q *queue.Queue, id, sender, rcpt, domain string, utf8, eight bool, body []byte) {
	t.Helper()
	now := time.Now()
	env := &queue.Envelope{
		ID: id, Username: "user", Sender: sender,
		Recipients:  []queue.Recipient{{Address: rcpt, Domain: domain, Status: queue.StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    utf8,
		EightBit:    eight,
	}
	if body == nil {
		body = []byte("From: " + sender + "\r\nTo: " + rcpt + "\r\nSubject: t\r\n\r\nHi\r\n")
	}
	if err := q.Add(env, body); err != nil {
		t.Fatal(err)
	}
}

// ---- SMTPUTF8 / 8BITMIME ----

func TestASCIINoUTF8No8BitParams(t *testing.T) {
	mx := &fakeMX{startTLS: false, ext8bit: true, extUTF8: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	d := deliver.New(cfg, q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "a1", "a@ex.com", "b@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done
	lines := mx.mailLines()
	if len(lines) == 0 {
		t.Fatal("no MAIL")
	}
	if strings.Contains(lines[0], "SMTPUTF8") || strings.Contains(lines[0], "BODY=8BITMIME") {
		t.Fatalf("unexpected params: %s", lines[0])
	}
}

func TestSMTPUTF8Supported(t *testing.T) {
	mx := &fakeMX{extUTF8: true, ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	d := deliver.New(deliverCfg(), q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "u1", "björn@ex.com", "b@ex.com", "ex.com", true, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done
	lines := mx.mailLines()
	if len(lines) == 0 || !strings.Contains(lines[0], "SMTPUTF8") {
		t.Fatalf("MAIL=%v", lines)
	}
}

func TestSMTPUTF8MissingPermanent(t *testing.T) {
	mx := &fakeMX{extUTF8: false, ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.MaxAttempts = 1
	d := deliver.New(cfg, q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "u2", "björn@ex.com", "b@ex.com", "ex.com", true, false, nil)
	cancel, done := runDeliverer(t, d)
	awaitSession(t, mx, 3*time.Second)
	cancel()
	<-done
	if mx.anyData() {
		t.Fatal("DATA must not be sent")
	}
	ids, _ := q.DeadIDs()
	if len(ids) == 0 {
		t.Fatal("expected permanent bury")
	}
	env, err := q.LoadDead(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(env.Recipients[0].Detail, "SMTPUTF8") {
		t.Fatalf("detail=%q", env.Recipients[0].Detail)
	}
}

func Test8BitMIMESupported(t *testing.T) {
	mx := &fakeMX{ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	d := deliver.New(deliverCfg(), q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	body := []byte("From: a@ex.com\r\nTo: b@ex.com\r\nSubject: t\r\n\r\n" + "caf\xc3\xa9\r\n")
	addEnvelope(t, q, "e1", "a@ex.com", "b@ex.com", "ex.com", false, true, body)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done
	lines := mx.mailLines()
	if len(lines) == 0 || !strings.Contains(lines[0], "BODY=8BITMIME") {
		t.Fatalf("MAIL=%v", lines)
	}
}

func Test8BitMIMEMissingPermanent(t *testing.T) {
	mx := &fakeMX{ext8bit: false, extUTF8: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.MaxAttempts = 1
	d := deliver.New(cfg, q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	body := []byte("From: a@ex.com\r\nTo: b@ex.com\r\nSubject: t\r\n\r\n" + "caf\xc3\xa9\r\n")
	addEnvelope(t, q, "e2", "a@ex.com", "b@ex.com", "ex.com", false, true, body)
	cancel, done := runDeliverer(t, d)
	awaitSession(t, mx, 3*time.Second)
	cancel()
	<-done
	if mx.anyData() {
		t.Fatal("DATA must not be sent")
	}
	ids, _ := q.DeadIDs()
	if len(ids) == 0 {
		t.Fatal("expected bury")
	}
	env, _ := q.LoadDead(ids[0])
	if !strings.Contains(env.Recipients[0].Detail, "8BITMIME") {
		t.Fatalf("detail=%q", env.Recipients[0].Detail)
	}
}

func TestBothCapabilitiesRequired(t *testing.T) {
	mx := &fakeMX{extUTF8: true, ext8bit: false}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.MaxAttempts = 1
	d := deliver.New(cfg, q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	body := []byte("From: björn@ex.com\r\nTo: b@ex.com\r\nSubject: t\r\n\r\n" + "caf\xc3\xa9\r\n")
	addEnvelope(t, q, "b1", "björn@ex.com", "b@ex.com", "ex.com", true, true, body)
	cancel, done := runDeliverer(t, d)
	awaitSession(t, mx, 3*time.Second)
	cancel()
	<-done
	if mx.anyData() {
		t.Fatal("missing 8BITMIME must block DATA")
	}
}

func TestClientUTF8OptInASCIINotRequired(t *testing.T) {
	mx := &fakeMX{extUTF8: false, ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	d := deliver.New(deliverCfg(), q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "opt1", "a@ex.com", "b@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done
}

func TestUTF8LocalPartCasingPreserved(t *testing.T) {
	mx := &fakeMX{extUTF8: true, ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	d := deliver.New(deliverCfg(), q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	sender := "Jörg.User@ex.com"
	rcpt := "Åke@ex.com"
	addEnvelope(t, q, "case1", sender, rcpt, "ex.com", true, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done
	lines := mx.mailLines()
	if len(lines) == 0 || !strings.Contains(lines[0], "Jörg.User@ex.com") {
		t.Fatalf("MAIL casing: %v", lines)
	}
}

// ---- TLS policy ----

func TestTLSAbsentPlainAllowed(t *testing.T) {
	cert, _, _ := mintCert(t, "mx.ex.com")
	mx := &fakeMX{startTLS: false, cert: cert, ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	d := deliver.New(deliverCfg(), q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "tls1", "a@ex.com", "b@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done
	if mx.conns.Load() != 1 {
		t.Fatalf("conns=%d", mx.conns.Load())
	}
}

func TestTLSAbsentRequired(t *testing.T) {
	cert, _, _ := mintCert(t, "mx.ex.com")
	mx := &fakeMX{startTLS: false, cert: cert}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.TLSMode = "required"
	allow := false
	cfg.Delivery.AllowPlaintext = &allow
	cfg.Delivery.MaxAttempts = 1
	d := deliver.New(cfg, q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "tls2", "a@ex.com", "b@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	awaitSession(t, mx, 3*time.Second)
	cancel()
	<-done
	if mx.anyData() {
		t.Fatal("must not DATA")
	}
}

func TestTLSVerifiedTrusted(t *testing.T) {
	cert, pool, _ := mintCert(t, "mx.ex.com")
	mx := &fakeMX{startTLS: true, cert: cert, ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.TLSMode = "opportunistic"
	cfg.Delivery.RequireValidMXTLSCert = true
	d := deliver.New(cfg, q, memLog{})
	d.SetTLSRootCAs(pool)
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "tls3", "a@ex.com", "b@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done
	mx.mu.Lock()
	var sni string
	var ehlos int
	for _, s := range mx.sessions {
		sni = s.sni
		for _, c := range s.commands {
			if strings.HasPrefix(strings.ToUpper(c), "EHLO ") {
				ehlos++
				if !strings.Contains(c, "outboxd.test") {
					t.Fatalf("EHLO hostname: %s", c)
				}
			}
		}
	}
	mx.mu.Unlock()
	if sni != "mx.ex.com" {
		t.Fatalf("SNI=%q", sni)
	}
	if ehlos < 2 {
		t.Fatalf("expected re-EHLO after TLS, ehlos=%d", ehlos)
	}
	if mx.conns.Load() != 1 {
		t.Fatalf("conns=%d want 1", mx.conns.Load())
	}
}

func TestTLSUntrustedNoInsecureRetry(t *testing.T) {
	cert, _, _ := mintCert(t, "mx.ex.com")
	mx := &fakeMX{startTLS: true, cert: cert, ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.TLSMode = "opportunistic"
	cfg.Delivery.RequireValidMXTLSCert = true
	cfg.Delivery.MaxAttempts = 1
	d := deliver.New(cfg, q, memLog{})
	d.SetTLSRootCAs(x509.NewCertPool())
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "tls4", "a@ex.com", "b@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	awaitSession(t, mx, 3*time.Second)
	cancel()
	<-done
	if mx.anyData() {
		t.Fatal("must not deliver after verify fail")
	}
	if mx.conns.Load() != 1 {
		t.Fatalf("must not reconnect insecurely, conns=%d", mx.conns.Load())
	}
}

func TestTLSInsecureModeSingleConn(t *testing.T) {
	cert, _, _ := mintCert(t, "mx.ex.com")
	mx := &fakeMX{startTLS: true, cert: cert, ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.TLSMode = "opportunistic_insecure"
	cfg.Delivery.RequireValidMXTLSCert = false
	d := deliver.New(cfg, q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "tls5", "a@ex.com", "b@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done
	if mx.conns.Load() != 1 {
		t.Fatalf("conns=%d want 1", mx.conns.Load())
	}
}

func TestTLSStartTLSCommandError(t *testing.T) {
	cert, pool, _ := mintCert(t, "mx.ex.com")
	mx := &fakeMX{startTLS: true, cert: cert, startTLSEr: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.MaxAttempts = 1
	d := deliver.New(cfg, q, memLog{})
	d.SetTLSRootCAs(pool)
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "tls6", "a@ex.com", "b@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	awaitSession(t, mx, 3*time.Second)
	cancel()
	<-done
	if mx.anyData() {
		t.Fatal("no plaintext DATA after STARTTLS error")
	}
}

func TestOrdinaryDeliveryPathRegression(t *testing.T) {
	cert, pool, _ := mintCert(t, "mx.ex.com")
	mx := &fakeMX{startTLS: true, cert: cert, ext8bit: true, extUTF8: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	d := deliver.New(cfg, q, memLog{})
	d.SetTLSRootCAs(pool)
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	body := []byte("From: sender@ex.com\r\nTo: dest@ex.com\r\nSubject: hello\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nHello world\r\n")
	addEnvelope(t, q, "reg1", "sender@ex.com", "dest@ex.com", "ex.com", false, false, body)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	// Wait session end so Finish can complete before inspecting queue.
	awaitSession(t, mx, 3*time.Second)
	cancel()
	<-done
	if q.Len() != 0 {
		t.Fatal("queue should finish")
	}
	if mx.conns.Load() != 1 {
		t.Fatalf("conns=%d", mx.conns.Load())
	}
}

func TestMultiMXUTF8Fallback(t *testing.T) {
	mxBad := &fakeMX{extUTF8: false, ext8bit: true}
	mxGood := &fakeMX{extUTF8: true, ext8bit: true}
	addrBad := startFakeMX(t, mxBad)
	addrGood := startFakeMX(t, mxGood)

	q := openQueue(t)
	d := deliver.New(deliverCfg(), q, memLog{})
	hostBad, _, _ := net.SplitHostPort(addrBad)
	hostGood, _, _ := net.SplitHostPort(addrGood)
	d.SetResolver(&fakeResolver{
		mx: map[string][]*net.MX{"ex.com": {
			{Host: "mx1.ex.com.", Pref: 10},
			{Host: "mx2.ex.com.", Pref: 20},
		}},
		ips: map[string][]net.IP{
			"mx1.ex.com": {net.ParseIP(hostBad)},
			"mx2.ex.com": {net.ParseIP(hostGood)},
		},
	})
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		var nd net.Dialer
		_, port, _ := net.SplitHostPort(address)
		_, pBad, _ := net.SplitHostPort(addrBad)
		if port == pBad {
			return nd.DialContext(ctx, "tcp", addrBad)
		}
		return nd.DialContext(ctx, "tcp", addrGood)
	}))
	addEnvelope(t, q, "mxf", "björn@ex.com", "b@ex.com", "ex.com", true, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mxGood.dataDone, 4*time.Second, "good MX DATA")
	cancel()
	<-done
	if mxBad.anyData() {
		t.Fatal("bad MX must not receive DATA")
	}
	_ = hostGood
}
