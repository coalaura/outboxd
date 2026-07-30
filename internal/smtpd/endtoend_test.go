package smtpd

import (
	"bufio"
	"bytes"
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

	"github.com/coalaura/outboxd/internal/deliver"
	"github.com/emersion/go-msgauth/dkim"
)

func TestEndToEndLocalPath(t *testing.T) {
	const password = "e2e-password-xyz"
	srv, cfg, spool, signer, roots := testServerWithUser(t, password)

	cert, mxPool := mintOutboundCert(t, "mx.ex.com")
	mx := &e2eMX{startTLS: true, cert: cert, ext8bit: true}
	mxAddr := startE2EMX(t, mx)

	d := deliver.New(cfg, spool, testLog{})
	d.SetTLSRootCAs(mxPool)
	ip := net.ParseIP("10.255.220.1")
	d.SetResolver(&e2eResolver{
		mx:  map[string][]*net.MX{"ex.com": {{Host: "mx.ex.com.", Pref: 10}}},
		ips: map[string][]net.IP{"mx.ex.com": {ip}},
	})
	d.SetDialer(e2eDial(func(ctx context.Context, network, address string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", mxAddr)
	}))

	entered := waitServeEntered(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Run(ctx) }()
	awaitCh(t, entered, 3*time.Second, "serve")

	delivDone := make(chan error, 1)
	dctx, dcancel := context.WithCancel(context.Background())
	go func() { delivDone <- d.Run(dctx) }()

	cl := dialSTARTTLS(t, srv.starttls.Addr, roots)
	cl.authPlain(t, "alice", password)
	cl.cmd(t, "MAIL FROM:<Alice.Sender@test.example>", 250)
	cl.cmd(t, "RCPT TO:<Dest.User@ex.com>", 250)
	cl.writeLine("DATA")
	cl.readCode(t, 354)
	body := "From: Alice.Sender@test.example\r\nTo: Dest.User@ex.com\r\nSubject: e2e hello\r\n\r\nBody of the ordinary path.\r\n.\r\n"
	_, _ = io.WriteString(cl.conn, body)
	cl.readCode(t, 250)
	cl.close()

	select {
	case <-mx.dataDone:
	case <-time.After(5 * time.Second):
		t.Fatal("outbound DATA timeout")
	}
	select {
	case <-mx.sessionDone:
	case <-time.After(5 * time.Second):
		t.Fatal("mx session timeout")
	}

	dcancel()
	select {
	case <-delivDone:
	case <-time.After(5 * time.Second):
		t.Fatal("deliverer hang")
	}

	if spool.Len() != 0 {
		t.Fatalf("queue nonempty after successful delivery: %d", spool.Len())
	}
	if mx.conns.Load() != 1 {
		t.Fatalf("outbound conns=%d want 1", mx.conns.Load())
	}
	snap := mx.snapshot()
	if !snap.tls || snap.sni != "mx.ex.com" {
		t.Fatalf("tls=%v sni=%q", snap.tls, snap.sni)
	}
	if !snap.data {
		t.Fatal("missing DATA")
	}
	var ehlos int
	var sawStartTLS, sawMail, sawRcpt bool
	for _, c := range snap.commands {
		u := strings.ToUpper(c)
		switch {
		case strings.HasPrefix(u, "EHLO "):
			ehlos++
			if !strings.Contains(c, cfg.Server.Hostname) {
				t.Fatalf("EHLO hostname: %s", c)
			}
		case strings.HasPrefix(u, "STARTTLS"):
			sawStartTLS = true
		case strings.HasPrefix(u, "MAIL FROM:"):
			sawMail = true
			if !strings.Contains(c, "Alice.Sender@test.example") {
				t.Fatalf("MAIL=%s", c)
			}
		case strings.HasPrefix(u, "RCPT TO:"):
			sawRcpt = true
			if !strings.Contains(c, "Dest.User@ex.com") {
				t.Fatalf("RCPT=%s", c)
			}
		}
	}
	if ehlos < 2 || !sawStartTLS || !sawMail || !sawRcpt {
		t.Fatalf("protocol incomplete ehlos=%d starttls=%v mail=%v rcpt=%v cmds=%v", ehlos, sawStartTLS, sawMail, sawRcpt, snap.commands)
	}
	if !strings.Contains(snap.dataBody, "DKIM-Signature:") {
		t.Fatal("DATA missing DKIM-Signature header")
	}
	if !strings.Contains(snap.dataBody, "Body of the ordinary path.") {
		t.Fatal("body not preserved")
	}
	verifs, err := dkim.VerifyWithOptions(bytes.NewReader([]byte(snap.dataBody)), &dkim.VerifyOptions{
		LookupTXT: func(domain string) ([]string, error) {
			if strings.Contains(domain, cfg.DKIM.Selector) && strings.Contains(domain, cfg.Server.Domain) {
				return []string{signer.Record()}, nil
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("dkim verify: %v", err)
	}
	if len(verifs) == 0 || verifs[0].Err != nil {
		t.Fatalf("dkim verifs=%+v", verifs)
	}

	cancel()
	select {
	case <-serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("submission serve hang")
	}
}

type e2eSnap struct {
	commands []string
	mail     string
	rcpt     string
	data     bool
	dataBody string
	tls      bool
	sni      string
}

type e2eMX struct {
	ln          net.Listener
	conns       atomic.Int64
	mu          sync.Mutex
	sess        e2eSnap
	dataDone    chan struct{}
	dataOnce    sync.Once
	sessionDone chan struct{}
	startTLS    bool
	ext8bit     bool
	cert        tls.Certificate
}

type e2eLive struct {
	mu       sync.Mutex
	commands []string
	mail     string
	rcpt     string
	data     bool
	body     strings.Builder
	tls      bool
	sni      string
}

func (l *e2eLive) snap() e2eSnap {
	l.mu.Lock()
	defer l.mu.Unlock()
	return e2eSnap{
		commands: append([]string(nil), l.commands...),
		mail:     l.mail,
		rcpt:     l.rcpt,
		data:     l.data,
		dataBody: l.body.String(),
		tls:      l.tls,
		sni:      l.sni,
	}
}

func startE2EMX(t *testing.T, mx *e2eMX) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mx.ln = ln
	mx.dataDone = make(chan struct{})
	mx.sessionDone = make(chan struct{}, 4)
	go mx.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func (mx *e2eMX) serve() {
	for {
		c, err := mx.ln.Accept()
		if err != nil {
			return
		}
		mx.conns.Add(1)
		live := &e2eLive{}
		go func() {
			mx.handle(c, live)
			mx.mu.Lock()
			mx.sess = live.snap()
			mx.mu.Unlock()
			mx.sessionDone <- struct{}{}
		}()
	}
}

func (mx *e2eMX) snapshot() e2eSnap {
	mx.mu.Lock()
	defer mx.mu.Unlock()
	return mx.sess
}

func (mx *e2eMX) handle(c net.Conn, live *e2eLive) {
	defer c.Close()
	rw := c
	br := bufio.NewReader(rw)
	write := func(s string) { _, _ = io.WriteString(rw, s) }
	write("220 mx.ex.com ESMTP\r\n")
	secured := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		raw := strings.TrimRight(line, "\r\n")
		live.mu.Lock()
		live.commands = append(live.commands, raw)
		live.mu.Unlock()
		upper := strings.ToUpper(raw)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			write("250-mx.ex.com\r\n")
			if mx.startTLS && !secured {
				write("250-STARTTLS\r\n")
			}
			if mx.ext8bit {
				write("250-8BITMIME\r\n")
			}
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "STARTTLS"):
			write("220 ready\r\n")
			tc := tls.Server(rw, &tls.Config{Certificates: []tls.Certificate{mx.cert}})
			if err := tc.Handshake(); err != nil {
				return
			}
			cs := tc.ConnectionState()
			live.mu.Lock()
			live.tls = true
			live.sni = cs.ServerName
			live.mu.Unlock()
			rw = tc
			br = bufio.NewReader(rw)
			secured = true
		case strings.HasPrefix(upper, "MAIL FROM:"):
			live.mu.Lock()
			live.mail = raw
			live.mu.Unlock()
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "RCPT TO:"):
			live.mu.Lock()
			live.rcpt = raw
			live.mu.Unlock()
			write("250 OK\r\n")
		case strings.HasPrefix(upper, "DATA"):
			live.mu.Lock()
			live.data = true
			live.mu.Unlock()
			write("354 go\r\n")
			for {
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(l, "\r\n") == "." {
					break
				}
				live.mu.Lock()
				live.body.WriteString(l)
				live.mu.Unlock()
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

type e2eResolver struct {
	mx  map[string][]*net.MX
	ips map[string][]net.IP
}

func (f *e2eResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if mx, ok := f.mx[name]; ok {
		out := make([]*net.MX, len(mx))
		copy(out, mx)
		return out, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *e2eResolver) LookupNetIP(ctx context.Context, network, host string) ([]net.IP, error) {
	ips, ok := f.ips[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IP, len(ips))
	copy(out, ips)
	return out, nil
}

type e2eDial func(ctx context.Context, network, address string) (net.Conn, error)

func (f e2eDial) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func mintOutboundCert(t *testing.T, cn string) (tls.Certificate, *x509.CertPool) {
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
