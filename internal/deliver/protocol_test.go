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
	"github.com/coalaura/outboxd/internal/deliver"
	"github.com/coalaura/outboxd/internal/mailbox"
	"github.com/coalaura/outboxd/internal/queue"
)

// sessionSnapshot is an immutable view of one SMTP session for tests.
type sessionSnapshot struct {
	Commands  []string
	MailLine  string
	RcptLines []string
	Data      bool
	DataBody  string
	TLS       bool
	SNI       string
}

// sessionLog records the SMTP conversation for one client connection.
// All mutable fields are protected by mu; tests must use snapshot().
type sessionLog struct {
	mu        sync.Mutex
	commands  []string
	mailLine  string
	rcptLines []string
	data      bool
	dataBody  strings.Builder
	tls       bool
	sni       string
}

func (s *sessionLog) add(cmd string) {
	s.mu.Lock()
	s.commands = append(s.commands, cmd)
	s.mu.Unlock()
}

func (s *sessionLog) snapshot() sessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := sessionSnapshot{
		MailLine: s.mailLine,
		Data:     s.data,
		DataBody: s.dataBody.String(),
		TLS:      s.tls,
		SNI:      s.sni,
	}
	out.Commands = append([]string(nil), s.commands...)
	out.RcptLines = append([]string(nil), s.rcptLines...)
	return out
}

// fakeMX is a deterministic MX, synchronized via readiness / event channels.
// mx.mu protects only the sessions slice and listener-level counters/flags
// that are configured before serve. Session fields use sessionLog.mu.
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
	// Buffered enough for test fan-out so completions are never dropped; never nonblocking-select-default.
	sessionDone chan struct{}
	// done closed when the accept loop stops.
	done chan struct{}

	startTLS   bool
	extUTF8    bool
	ext8bit    bool
	cert       tls.Certificate
	brokenTLS  bool // handshake fails after 220
	startTLSEr bool // STARTTLS command returns 454

	// captureBody records DATA octets when true.
	captureBody bool
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
	mx.sessionDone = make(chan struct{}, 256)
	mx.done = make(chan struct{})
	go mx.serve()
	close(mx.ready)
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-mx.done:
		case <-time.After(5 * time.Second):
		}
	})
	return ln.Addr().String()
}

func (mx *fakeMX) serve() {
	defer close(mx.done)
	var wg sync.WaitGroup
	for {
		c, err := mx.ln.Accept()
		if err != nil {
			wg.Wait()
			return
		}
		mx.conns.Add(1)
		log := &sessionLog{}
		mx.mu.Lock()
		mx.sessions = append(mx.sessions, log)
		mx.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			mx.handle(c, log)
			mx.sessionDone <- struct{}{}
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
			if mx.brokenTLS {
				// Fail during the handshake, not after a successful one.
				_, _ = rw.Write([]byte("NOT_TLS_HANDSHAKE"))
				return
			}
			cfg := &tls.Config{Certificates: []tls.Certificate{mx.cert}}
			tlsConn := tls.Server(rw, cfg)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			cs := tlsConn.ConnectionState()
			log.mu.Lock()
			log.sni = cs.ServerName
			log.tls = true
			log.mu.Unlock()
			rw = tlsConn
			br = bufio.NewReader(rw)
			secured = true
		case strings.HasPrefix(upper, "MAIL FROM:"):
			log.mu.Lock()
			log.mailLine = raw
			log.mu.Unlock()
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "RCPT TO:"):
			log.mu.Lock()
			log.rcptLines = append(log.rcptLines, raw)
			log.mu.Unlock()
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "DATA"):
			log.mu.Lock()
			log.data = true
			log.mu.Unlock()
			write("354 go\r\n")
			for {
				l, err := readLine()
				if err != nil {
					return
				}
				trimmed := strings.TrimRight(l, "\r\n")
				if trimmed == "." {
					break
				}
				if mx.captureBody {
					log.mu.Lock()
					log.dataBody.WriteString(l)
					log.mu.Unlock()
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

func (mx *fakeMX) snapshots() []sessionSnapshot {
	mx.mu.Lock()
	logs := append([]*sessionLog(nil), mx.sessions...)
	mx.mu.Unlock()
	out := make([]sessionSnapshot, 0, len(logs))
	for _, s := range logs {
		out = append(out, s.snapshot())
	}
	return out
}

func (mx *fakeMX) mailLines() []string {
	var out []string
	for _, s := range mx.snapshots() {
		if s.MailLine != "" {
			out = append(out, s.MailLine)
		}
	}
	return out
}

func (mx *fakeMX) anyData() bool {
	for _, s := range mx.snapshots() {
		if s.Data {
			return true
		}
	}
	return false
}

func (mx *fakeMX) anyMail() bool {
	return len(mx.mailLines()) > 0
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
	snaps := mx.snapshots()
	var sni string
	var ehlos int
	for _, s := range snaps {
		if s.SNI != "" {
			sni = s.SNI
		}
		for _, c := range s.Commands {
			if strings.HasPrefix(strings.ToUpper(c), "EHLO ") {
				ehlos++
				if !strings.Contains(c, "outboxd.test") {
					t.Fatalf("EHLO hostname: %s", c)
				}
			}
		}
	}
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

type mapDialer struct {
	m map[string]string // "ip:25" -> local listen addr
}

func (m mapDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	target, ok := m.m[address]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errUnmapped(address)}
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", target)
}

type errUnmapped string

func (e errUnmapped) Error() string { return "unmapped " + string(e) }

func multiMX(t *testing.T, bad, good *fakeMX) (*deliver.Deliverer, *queue.Queue) {
	t.Helper()
	addrBad := startFakeMX(t, bad)
	addrGood := startFakeMX(t, good)
	ipBad := net.ParseIP("10.255.200.1")
	ipGood := net.ParseIP("10.255.200.2")
	q := openQueue(t)
	d := deliver.New(deliverCfg(), q, memLog{})
	d.SetResolver(&fakeResolver{
		mx: map[string][]*net.MX{"ex.com": {
			{Host: "mx1.ex.com.", Pref: 10},
			{Host: "mx2.ex.com.", Pref: 20},
		}},
		ips: map[string][]net.IP{
			"mx1.ex.com": {ipBad},
			"mx2.ex.com": {ipGood},
		},
	})
	d.SetDialer(mapDialer{m: map[string]string{
		net.JoinHostPort(ipBad.String(), "25"):  addrBad,
		net.JoinHostPort(ipGood.String(), "25"): addrGood,
	}})
	return d, q
}

func TestMultiMXUTF8Fallback(t *testing.T) {
	mxBad := &fakeMX{extUTF8: false, ext8bit: true}
	mxGood := &fakeMX{extUTF8: true, ext8bit: true}
	d, q := multiMX(t, mxBad, mxGood)
	addEnvelope(t, q, "mxf", "björn@ex.com", "b@ex.com", "ex.com", true, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mxGood.dataDone, 4*time.Second, "good MX DATA")
	awaitSession(t, mxBad, 3*time.Second)
	cancel()
	<-done
	if mxBad.anyData() || mxBad.anyMail() {
		t.Fatal("bad MX must not receive MAIL/DATA")
	}
	if mxBad.conns.Load() != 1 || mxGood.conns.Load() != 1 {
		t.Fatalf("conns bad=%d good=%d", mxBad.conns.Load(), mxGood.conns.Load())
	}
	lines := mxGood.mailLines()
	if len(lines) == 0 || !strings.Contains(lines[0], "SMTPUTF8") {
		t.Fatalf("good MAIL=%v", lines)
	}
}

func TestMultiMX8BitFallback(t *testing.T) {
	mxBad := &fakeMX{extUTF8: true, ext8bit: false}
	mxGood := &fakeMX{extUTF8: true, ext8bit: true}
	d, q := multiMX(t, mxBad, mxGood)
	body := []byte("From: a@ex.com\r\nTo: b@ex.com\r\nSubject: t\r\n\r\n" + "caf\xc3\xa9\r\n")
	addEnvelope(t, q, "mx8", "a@ex.com", "b@ex.com", "ex.com", false, true, body)
	cancel, done := runDeliverer(t, d)
	await(t, mxGood.dataDone, 4*time.Second, "good DATA")
	awaitSession(t, mxBad, 3*time.Second)
	cancel()
	<-done
	if mxBad.anyMail() || mxBad.anyData() {
		t.Fatal("bad MX MAIL/DATA")
	}
	if mxBad.conns.Load() != 1 || mxGood.conns.Load() != 1 {
		t.Fatalf("conns bad=%d good=%d", mxBad.conns.Load(), mxGood.conns.Load())
	}
	lines := mxGood.mailLines()
	if len(lines) == 0 || !strings.Contains(lines[0], "BODY=8BITMIME") {
		t.Fatalf("MAIL=%v", lines)
	}
}

func TestMultiMXBothCapabilities(t *testing.T) {
	mxPartial := &fakeMX{extUTF8: true, ext8bit: false}
	mxFull := &fakeMX{extUTF8: true, ext8bit: true}
	d, q := multiMX(t, mxPartial, mxFull)
	body := []byte("From: björn@ex.com\r\nTo: b@ex.com\r\nSubject: t\r\n\r\n" + "caf\xc3\xa9\r\n")
	addEnvelope(t, q, "mxb", "björn@ex.com", "b@ex.com", "ex.com", true, true, body)
	cancel, done := runDeliverer(t, d)
	await(t, mxFull.dataDone, 4*time.Second, "full DATA")
	awaitSession(t, mxPartial, 3*time.Second)
	cancel()
	<-done
	if mxPartial.anyMail() || mxPartial.anyData() {
		t.Fatal("partial MX must not receive MAIL/DATA")
	}
	lines := mxFull.mailLines()
	if len(lines) != 1 || !strings.Contains(lines[0], "SMTPUTF8") || !strings.Contains(lines[0], "BODY=8BITMIME") {
		t.Fatalf("MAIL=%v", lines)
	}
}

func TestMultiMXAllLackCapability(t *testing.T) {
	mx1 := &fakeMX{extUTF8: false, ext8bit: true}
	mx2 := &fakeMX{extUTF8: false, ext8bit: true}
	addr1 := startFakeMX(t, mx1)
	addr2 := startFakeMX(t, mx2)
	ip1 := net.ParseIP("10.255.200.1")
	ip2 := net.ParseIP("10.255.200.2")
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.MaxAttempts = 1
	d := deliver.New(cfg, q, memLog{})
	d.SetResolver(&fakeResolver{
		mx: map[string][]*net.MX{"ex.com": {
			{Host: "mx1.ex.com.", Pref: 10},
			{Host: "mx2.ex.com.", Pref: 20},
		}},
		ips: map[string][]net.IP{
			"mx1.ex.com": {ip1},
			"mx2.ex.com": {ip2},
		},
	})
	d.SetDialer(mapDialer{m: map[string]string{
		net.JoinHostPort(ip1.String(), "25"): addr1,
		net.JoinHostPort(ip2.String(), "25"): addr2,
	}})
	addEnvelope(t, q, "mxall", "björn@ex.com", "b@ex.com", "ex.com", true, false, nil)
	cancel, done := runDeliverer(t, d)
	awaitSession(t, mx1, 3*time.Second)
	awaitSession(t, mx2, 3*time.Second)
	cancel()
	<-done
	if mx1.anyData() || mx2.anyData() {
		t.Fatal("no DATA")
	}
	ids, _ := q.DeadIDs()
	if len(ids) == 0 {
		t.Fatal("expected dead")
	}
	env, _ := q.LoadDead(ids[0])
	if !strings.Contains(env.Recipients[0].Detail, "SMTPUTF8") {
		t.Fatalf("detail=%q", env.Recipients[0].Detail)
	}
}

func TestMultiMXMixedNetworkAndCapability(t *testing.T) {
	mxCap := &fakeMX{extUTF8: false, ext8bit: true}
	addrCap := startFakeMX(t, mxCap)
	ipNet := net.ParseIP("10.255.201.1")
	ipCap := net.ParseIP("10.255.201.2")
	q := openQueue(t)
	cfg := deliverCfg()
	// Multiple attempts so a temporary outcome persists a retry rather than exhausting.
	cfg.Delivery.MaxAttempts = 5
	d := deliver.New(cfg, q, memLog{})
	d.SetResolver(&fakeResolver{
		mx: map[string][]*net.MX{"ex.com": {
			{Host: "mx-net.ex.com.", Pref: 10},
			{Host: "mx-cap.ex.com.", Pref: 20},
		}},
		ips: map[string][]net.IP{
			"mx-net.ex.com": {ipNet},
			"mx-cap.ex.com": {ipCap},
		},
	})
	d.SetDialer(mapDialer{m: map[string]string{
		net.JoinHostPort(ipCap.String(), "25"): addrCap,
	}})
	addEnvelope(t, q, "mix1", "björn@ex.com", "b@ex.com", "ex.com", true, false, nil)

	// Deliverer will retry; cancel after first MX hosts have been tried (cap session ended).
	cancel, done := runDeliverer(t, d)
	awaitSession(t, mxCap, 3*time.Second)
	// Give Finish path no permanent reject: wait for retry persistence by cancelling after session.
	cancel()
	<-done
	if mxCap.anyData() {
		t.Fatal("no DATA")
	}
	ids, _ := q.DeadIDs()
	if len(ids) != 0 {
		t.Fatalf("must not permanently bury on mixed temporary+capability, dead=%v", ids)
	}
	// Message remains pending for retry (not finished).
	if q.Len() == 0 {
		t.Fatal("expected message still queued for retry")
	}
}

func TestTLSHandshakeFailure(t *testing.T) {
	cert, pool, _ := mintCert(t, "mx.ex.com")
	mx := &fakeMX{startTLS: true, cert: cert, brokenTLS: true, ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.MaxAttempts = 1
	d := deliver.New(cfg, q, memLog{})
	d.SetTLSRootCAs(pool)
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "tls7", "a@ex.com", "b@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	awaitSession(t, mx, 3*time.Second)
	cancel()
	<-done
	if mx.anyData() || mx.anyMail() {
		t.Fatal("no MAIL/DATA after handshake failure")
	}
	if mx.conns.Load() != 1 {
		t.Fatalf("no policy-changing reconnect, conns=%d", mx.conns.Load())
	}
}

func TestTLSCandidateIPRetryKeepsPolicy(t *testing.T) {
	cert, pool, _ := mintCert(t, "mx.ex.com")
	mx := &fakeMX{startTLS: true, cert: cert, ext8bit: true}
	addr := startFakeMX(t, mx)
	ipBad := net.ParseIP("10.255.202.1")
	ipGood := net.ParseIP("10.255.202.2")
	q := openQueue(t)
	cfg := deliverCfg()
	cfg.Delivery.RequireValidMXTLSCert = true
	d := deliver.New(cfg, q, memLog{})
	d.SetTLSRootCAs(pool)
	d.SetResolver(&fakeResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.ex.com": {ipBad, ipGood}},
	})
	var dials []string
	var mu sync.Mutex
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, address)
		mu.Unlock()
		host, _, _ := net.SplitHostPort(address)
		if host == ipBad.String() {
			return nil, errors.New("network down")
		}
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", addr)
	}))
	addEnvelope(t, q, "ipfail", "a@ex.com", "b@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 4*time.Second, "DATA")
	cancel()
	<-done
	// Deterministic dial order is asserted in package deliver TestCandidateIPFallbackOrder.
	// Here, success pathway: one verified STARTTLS connection, one MAIL/DATA.
	if mx.conns.Load() != 1 {
		t.Fatalf("conns=%d", mx.conns.Load())
	}
	snaps := mx.snapshots()
	if len(snaps) != 1 || !snaps[0].TLS || !snaps[0].Data {
		t.Fatalf("expected one TLS DATA session, snaps=%+v", snaps)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dials) == 0 {
		t.Fatal("expected dials")
	}
	_ = dials
}

func TestIDNARoutingUsesALabel(t *testing.T) {
	mx := &fakeMX{extUTF8: true, ext8bit: true}
	addr := startFakeMX(t, mx)
	host, _, _ := net.SplitHostPort(addr)
	q := openQueue(t)
	d := deliver.New(deliverCfg(), q, memLog{})

	unicodeDomain := "exämple.com"
	routing, err := mailbox.RoutingDomain(unicodeDomain)
	if err != nil {
		t.Fatal(err)
	}
	if routing == unicodeDomain || strings.Contains(routing, "ä") {
		t.Fatalf("expected A-label got %q", routing)
	}

	var lookedMX []string
	res := &recordingResolver{
		fakeResolver: fakeResolver{
			mx:  map[string][]*net.MX{routing: {{Host: "mx." + routing + ".", Pref: 10}}},
			ips: map[string][]net.IP{"mx." + routing: {net.ParseIP(host)}},
		},
		mxLookups: &lookedMX,
	}
	d.SetResolver(res)
	d.SetDialer(dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", addr)
	}))

	rcpt := "User@exämple.com"
	addEnvelope(t, q, "idna1", "a@ex.com", rcpt, routing, true, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done

	if len(lookedMX) == 0 || lookedMX[0] != routing {
		t.Fatalf("MX lookups=%v want first %q", lookedMX, routing)
	}
	for _, name := range lookedMX {
		if strings.Contains(name, "ä") {
			t.Fatalf("DNS used U-label %q", name)
		}
	}
	snaps := mx.snapshots()
	rcptLine := ""
	if len(snaps) > 0 && len(snaps[0].RcptLines) > 0 {
		rcptLine = snaps[0].RcptLines[0]
	}
	if !strings.Contains(rcptLine, "User@exämple.com") {
		t.Fatalf("RCPT must preserve submitted mailbox, got %q", rcptLine)
	}
}

type recordingResolver struct {
	fakeResolver
	mxLookups *[]string
}

func (r *recordingResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	*r.mxLookups = append(*r.mxLookups, name)
	return r.fakeResolver.LookupMX(ctx, name)
}

func TestQueueDomainMismatchRejected(t *testing.T) {
	q := openQueue(t)
	now := time.Now()
	env := &queue.Envelope{
		ID: "badmeta", Username: "u", Sender: "a@ex.com",
		Recipients:  []queue.Recipient{{Address: "b@ex.com", Domain: "other.com", Status: queue.StatusPending}},
		Created:     now,
		NextAttempt: now,
	}
	if err := q.Add(env, []byte("From: a@ex.com\r\nTo: b@ex.com\r\nSubject: t\r\n\r\nHi\r\n")); err == nil {
		t.Fatal("expected domain mismatch")
	}
}

func TestQueueDomainALabelAccepted(t *testing.T) {
	q := openQueue(t)
	now := time.Now()
	routing, err := mailbox.RoutingDomain("exämple.com")
	if err != nil {
		t.Fatal(err)
	}
	env := &queue.Envelope{
		ID: "goodmeta", Username: "u", Sender: "a@ex.com",
		Recipients:  []queue.Recipient{{Address: "b@exämple.com", Domain: routing, Status: queue.StatusPending}},
		Created:     now,
		NextAttempt: now,
		SMTPUTF8:    true,
	}
	if err := q.Add(env, []byte("From: a@ex.com\r\nTo: b@exämple.com\r\nSubject: t\r\n\r\nHi\r\n")); err != nil {
		t.Fatal(err)
	}
}

func TestBothParamsRequiredSingleMAIL(t *testing.T) {
	mx := &fakeMX{extUTF8: true, ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	d := deliver.New(deliverCfg(), q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	body := []byte("From: björn@ex.com\r\nTo: b@ex.com\r\nSubject: t\r\n\r\n" + "caf\xc3\xa9\r\n")
	addEnvelope(t, q, "bothp", "björn@ex.com", "b@ex.com", "ex.com", true, true, body)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done
	lines := mx.mailLines()
	if len(lines) != 1 {
		t.Fatalf("want one MAIL, got %v", lines)
	}
	if !strings.Contains(lines[0], "SMTPUTF8") || !strings.Contains(lines[0], "BODY=8BITMIME") {
		t.Fatalf("MAIL=%s", lines[0])
	}
}

func TestASCIIRCPTCasingPreserved(t *testing.T) {
	mx := &fakeMX{ext8bit: true}
	addr := startFakeMX(t, mx)
	q := openQueue(t)
	d := deliver.New(deliverCfg(), q, memLog{})
	wireMX(t, d, "ex.com", "mx.ex.com", addr)
	addEnvelope(t, q, "case2", "a@ex.com", "User.Name@ex.com", "ex.com", false, false, nil)
	cancel, done := runDeliverer(t, d)
	await(t, mx.dataDone, 3*time.Second, "DATA")
	cancel()
	<-done
	snaps := mx.snapshots()
	rcptLine := ""
	if len(snaps) > 0 && len(snaps[0].RcptLines) > 0 {
		rcptLine = snaps[0].RcptLines[0]
	}
	if !strings.Contains(rcptLine, "User.Name@ex.com") {
		t.Fatalf("RCPT=%q", rcptLine)
	}
}
