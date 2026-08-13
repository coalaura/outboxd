package smtpd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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
	"github.com/coalaura/outboxd/internal/passwd"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/coalaura/outboxd/internal/sign"
	"github.com/emersion/go-smtp"
)

type submissionMessageSizeCase struct {
	name string
	size int64
	code int
}

type originatorHeaderCase struct {
	name   string
	header string
}

type dataDeadlineQueueAddCase struct {
	name     string
	err      error
	accepted bool
}

type captureLog struct {
	mu   sync.Mutex
	text strings.Builder
}

func (l *captureLog) Printf(format string, values ...any) {
	l.mu.Lock()
	fmt.Fprintf(&l.text, format, values...)
	l.mu.Unlock()
}

func (l *captureLog) Println(values ...any) {
	l.mu.Lock()
	fmt.Fprintln(&l.text, values...)
	l.mu.Unlock()
}

func (l *captureLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.text.String()
}

// testServerWithUser builds a submission stack with one Argon2id user and DKIM.
func testServerWithUser(t *testing.T, password string) (*Server, *config.Config, *queue.Queue, *sign.Signer, *x509.CertPool) {
	t.Helper()

	base := t.TempDir()

	cfgPath := filepath.Join(base, "config.yml")
	dataDir := filepath.Join(base, "data")

	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		t.Fatal(err)
	}

	body := strings.Join([]string{
		"server:",
		"  hostname: mail.test.example",
		"  domain: test.example",
		"  data_directory: " + filepath.ToSlash(dataDir),
		"  max_message_bytes: 1048576",
		"  max_recipients: 10",
		"  max_messages_per_hour: 1000",
		"  max_recipients_per_hour: 10000",
		"  read_timeout: 1m",
		"  write_timeout: 1m",
		"  submission_addr: \"127.0.0.1:0\"",
		"  implicit_tls_addr: \"\"",
		"  disable_implicit_tls: true",
		"  max_connections: 16",
		"  max_connections_per_ip: 8",
		"  auth_workers: 2",
		"tls:",
		"  mode: self_signed",
		"  certificate_file: tls/server.crt",
		"  private_key_file: tls/server.key",
		"  minimum_version: \"1.2\"",
		"dkim:",
		"  selector: mail",
		"  private_key_file: dkim/mail.key",
		"  headers:",
		"    - From",
		"    - Sender",
		"    - To",
		"    - Subject",
		"    - Date",
		"    - Message-ID",
		"delivery:",
		"  tls_mode: opportunistic",
		"  max_attempts: 3",
		"  maximum_lifetime: 1h",
		"  initial_retry_delay: 1s",
		"  maximum_retry_delay: 1m",
		"  domain_concurrency: 1",
		"  global_concurrency: 2",
		"  connection_timeout: 5s",
		"  command_timeout: 30s",
		"  submission_timeout: 1m",
		"  allow_private_destinations: true",
		"dns:",
		"  dmarc_policy: none",
		"  output_file: dns-records.txt",
		"",
	}, "\n")

	err = os.WriteFile(cfgPath, []byte(body), 0600)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	hash, err := passwd.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.AddUser(config.User{
		Username:       "alice",
		PasswordHash:   hash,
		Enabled:        true,
		AllowedSenders: []string{"Alice.Sender@test.example", "alice@test.example"},
	})

	if err != nil {
		t.Fatal(err)
	}

	k, _, err := certs.Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	signer, _, err := sign.Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}

	spool, err := queue.OpenDefault(filepath.Join(dataDir, "queue"))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = spool.Close()
	})

	srv := New(cfg, k, signer, spool, testLog{})

	err = srv.Listen()
	if err != nil {
		t.Fatal(err)
	}

	// Trust self-signed submission cert.
	pool := x509.NewCertPool()

	raw, err := os.ReadFile(cfg.ResolvePath(cfg.TLS.CertificateFile))
	if err != nil {
		t.Fatal(err)
	}

	for {
		var block *pem.Block

		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}

		pool.AddCert(c)
	}

	return srv, cfg, spool, signer, pool
}

type smtpClient struct {
	conn net.Conn
	br   *bufio.Reader
	cmds []string
}

func dialSTARTTLS(t *testing.T, addr string, roots *x509.CertPool) *smtpClient {
	t.Helper()

	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	cl := &smtpClient{conn: c, br: bufio.NewReader(c)}

	cl.readCode(t, 220)

	cl.cmd(t, "EHLO client.test", 250)

	cl.writeLine("STARTTLS")

	cl.readCode(t, 220)

	tlsConn := tls.Client(c, &tls.Config{
		ServerName: "mail.test.example",
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})

	err = tlsConn.Handshake()
	if err != nil {
		t.Fatal(err)
	}

	cl.conn = tlsConn
	cl.br = bufio.NewReader(tlsConn)

	cl.cmd(t, "EHLO client.test", 250)

	return cl
}

func (c *smtpClient) writeLine(s string) {
	c.cmds = append(c.cmds, s)

	_, _ = io.WriteString(c.conn, s+"\r\n")
}

func (c *smtpClient) readCode(t *testing.T, want int) string {
	t.Helper()

	var last string

	for {
		line, err := c.br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}

		last = strings.TrimRight(line, "\r\n")
		if len(last) < 4 {
			t.Fatalf("short reply %q", last)
		}

		var code int

		fmt.Sscanf(last[:3], "%d", &code)

		if last[3] == ' ' {
			if code != want {
				t.Fatalf("want %d got %q", want, last)
			}

			return last
		}

		if last[3] != '-' {
			t.Fatalf("bad reply %q", last)
		}
	}
}

func (c *smtpClient) cmd(t *testing.T, line string, want int) string {
	t.Helper()

	c.writeLine(line)

	return c.readCode(t, want)
}

func (c *smtpClient) cmdLines(t *testing.T, line string, want int) []string {
	t.Helper()

	c.writeLine(line)

	var lines []string

	for {
		response, err := c.br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}

		response = strings.TrimRight(response, "\r\n")

		lines = append(lines, response)
		if len(response) < 4 {
			t.Fatalf("short reply %q", response)
		}

		var code int

		fmt.Sscanf(response[:3], "%d", &code)
		if code != want {
			t.Fatalf("want %d got %q", want, response)
		}

		if response[3] == ' ' {
			return lines
		}
	}
}

func (c *smtpClient) authPlain(t *testing.T, user, pass string) {
	t.Helper()

	payload := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pass))

	c.cmd(t, "AUTH PLAIN "+payload, 235)
}

func (c *smtpClient) close() {
	_ = c.conn.Close()
}

func (c *smtpClient) expectClosed(t *testing.T) {
	t.Helper()

	_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	_, err := c.br.ReadByte()
	if err == nil {
		t.Fatal("connection remained open after DATA admission denial")
	}
}

func runTestSubmission(t *testing.T, srv *Server) {
	t.Helper()

	entered := waitServeEntered(t, srv)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- srv.Run(ctx)
	}()

	awaitCh(t, entered, 3*time.Second, "serve")

	t.Cleanup(func() {
		cancel()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("submission server did not stop")
		}
	})
}

func beginMessage(t *testing.T, cl *smtpClient, bodyOpt string) {
	t.Helper()

	mail := "MAIL FROM:<Alice.Sender@test.example>"
	if bodyOpt != "" {
		mail += " BODY=" + bodyOpt
	}

	cl.cmd(t, mail, 250)
	cl.cmd(t, "RCPT TO:<dest@example.com>", 250)
	cl.cmd(t, "DATA", 354)
}

func writeMessage(cl *smtpClient, body string) {
	_, _ = io.WriteString(cl.conn, "From: Alice.Sender@test.example\r\nTo: dest@example.com\r\nSubject: test\r\n\r\n"+body+"\r\n.\r\n")
}

func messageOfSize(size int64) string {
	const headers = "From: Alice.Sender@test.example\r\nTo: dest@example.com\r\nSubject: size test\r\n\r\n"

	remaining := int(size) - len(headers) - 2

	var body strings.Builder
	body.Grow(int(size))

	body.WriteString(headers)

	for remaining > 998 {
		body.WriteString(strings.Repeat("x", 998))
		body.WriteString("\r\n")

		remaining -= 1000
	}

	body.WriteString(strings.Repeat("x", remaining))
	body.WriteString("\r\n")

	return body.String()
}

func TestSubmissionMessageSizeBoundary(t *testing.T) {
	const password = "message-size-password"

	srv, cfg, _, _, pool := testServerWithUser(t, password)

	runTestSubmission(t, srv)

	for _, tt := range []submissionMessageSizeCase{
		{"exact maximum", cfg.Server.MaxMessageBytes, 250},
		{"one over maximum", cfg.Server.MaxMessageBytes + 1, 552},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cl := dialSTARTTLS(t, srv.starttls.Addr, pool)
			defer cl.close()

			cl.authPlain(t, "alice", password)

			beginMessage(t, cl, "")

			_, _ = io.WriteString(cl.conn, messageOfSize(tt.size)+".\r\n")

			cl.readCode(t, tt.code)
		})
	}
}

func TestSubmissionRecipientLimitCountsUniqueRecipients(t *testing.T) {
	const password = "unique-recipient-password"

	srv, cfg, spool, _, pool := testServerWithUser(t, password)

	cfg.Server.MaxRecipients = 2

	runTestSubmission(t, srv)

	cl := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer cl.close()

	cl.authPlain(t, "alice", password)

	cl.cmd(t, "MAIL FROM:<Alice.Sender@test.example>", 250)
	cl.cmd(t, "RCPT TO:<a@example.com>", 250)
	cl.cmd(t, "RCPT TO:<a@example.com>", 250)
	cl.cmd(t, "RCPT TO:<b@example.com>", 250)
	cl.cmd(t, "DATA", 354)

	writeMessage(cl, "unique recipients")

	cl.readCode(t, 250)

	env, err := spool.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(env.Recipients) != 2 || env.Recipients[0].Address != "a@example.com" || env.Recipients[1].Address != "b@example.com" {
		t.Fatalf("recipients=%v, want a@example.com and b@example.com", env.Recipients)
	}
}

func TestSubmissionSizeProtocolBoundaries(t *testing.T) {
	const password = "protocol-size-password"

	srv, cfg, _, _, pool := testServerWithUser(t, password)

	runTestSubmission(t, srv)

	cl := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer cl.close()

	lines := cl.cmdLines(t, "EHLO size.test", 250)

	wantCapability := fmt.Sprintf("SIZE %d", cfg.Server.MaxMessageBytes)
	if !strings.Contains(strings.Join(lines, "\n"), wantCapability) {
		t.Fatalf("EHLO capabilities %q do not contain %q", lines, wantCapability)
	}

	cl.authPlain(t, "alice", password)

	cl.cmd(t, fmt.Sprintf("MAIL FROM:<Alice.Sender@test.example> SIZE=%d", cfg.Server.MaxMessageBytes), 250)
	cl.cmd(t, "RSET", 250)
	cl.cmd(t, fmt.Sprintf("MAIL FROM:<Alice.Sender@test.example> SIZE=%d", cfg.Server.MaxMessageBytes+1), 552)

	for _, tt := range []submissionMessageSizeCase{
		{"exact maximum", cfg.Server.MaxMessageBytes, 250},
		{"one over maximum", cfg.Server.MaxMessageBytes + 1, 552},
	} {
		t.Run("BDAT "+tt.name, func(t *testing.T) {
			cl.cmd(t, "MAIL FROM:<Alice.Sender@test.example>", 250)
			cl.cmd(t, "RCPT TO:<dest@example.com>", 250)

			cl.writeLine(fmt.Sprintf("BDAT %d LAST", tt.size))

			_, _ = io.WriteString(cl.conn, messageOfSize(tt.size))

			cl.readCode(t, tt.code)
		})
	}
}

func TestSubmissionUnnecessarySMTPUTF8OptIn(t *testing.T) {
	const password = "test-password-xyz"

	srv, _, spool, _, pool := testServerWithUser(t, password)

	entered := waitServeEntered(t, srv)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		done <- srv.Run(ctx)
	}()

	awaitCh(t, entered, 3*time.Second, "serve")

	t.Cleanup(func() {
		cancel()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	cl := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer cl.close()

	cl.authPlain(t, "alice", password)

	// Opt in to SMTPUTF8 with fully ASCII envelope and body.
	cl.cmd(t, "MAIL FROM:<Alice.Sender@test.example> SMTPUTF8", 250)
	cl.cmd(t, "RCPT TO:<Bob.Recipient@example.com>", 250)

	cl.writeLine("DATA")

	cl.readCode(t, 354)

	msg := "From: Alice.Sender@test.example\r\nTo: Bob.Recipient@example.com\r\nSubject: ascii only\r\n\r\nHello world\r\n.\r\n"

	_, _ = io.WriteString(cl.conn, msg)

	cl.readCode(t, 250)

	// Pull the accepted envelope from the queue.
	env, err := spool.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if env.SMTPUTF8 {
		t.Fatal("unnecessary SMTPUTF8 opt-in must store SMTPUTF8=false")
	}

	if env.Sender != "Alice.Sender@test.example" {
		t.Fatalf("sender casing: %q", env.Sender)
	}

	if env.Recipients[0].Address != "Bob.Recipient@example.com" {
		t.Fatalf("rcpt casing: %q", env.Recipients[0].Address)
	}

	// Requeue so we do not leave the item active for delivery.
	spool.Requeue(env)
}

func TestDataProcessingSemaphoreNonblockingAndReleased(t *testing.T) {
	const password = "data-semaphore-password"

	srv, _, _, _, pool := testServerWithUser(t, password)

	srv.dataWork = make(chan struct{}, 1)

	runTestSubmission(t, srv)

	first := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer first.close()

	first.authPlain(t, "alice", password)

	beginMessage(t, first, "")

	_, _ = io.WriteString(first.conn, "From: Alice.Sender@test.example\r\nTo: dest@example.com\r\n\r\nblocked")

	deadline := time.Now().Add(3 * time.Second)

	for len(srv.dataWork) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if len(srv.dataWork) != 1 {
		t.Fatal("first DATA did not acquire processing slot")
	}

	second := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer second.close()

	second.authPlain(t, "alice", password)

	beginMessage(t, second, "")

	second.expectClosed(t)

	_, _ = io.WriteString(first.conn, "\r\n.\r\n")

	first.readCode(t, 250)

	if len(srv.dataWork) != 0 {
		t.Fatal("processing slot not released after success")
	}

	third := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer third.close()

	third.authPlain(t, "alice", password)

	beginMessage(t, third, "")
	writeMessage(third, "accepted after release")

	third.readCode(t, 250)
}

func TestIncompleteBDATAbsoluteDeadlineReleasesWorker(t *testing.T) {
	const password = "bdat-deadline-password"

	srv, cfg, _, _, pool := testServerWithUser(t, password)

	cfg.Server.ReadTimeout = "1s"

	srv.dataWork = make(chan struct{}, 1)

	runTestSubmission(t, srv)

	cl := dialSTARTTLS(t, srv.starttls.Addr, pool)

	cl.authPlain(t, "alice", password)

	cl.cmd(t, "MAIL FROM:<Alice.Sender@test.example>", 250)
	cl.cmd(t, "RCPT TO:<dest@example.com>", 250)
	cl.cmd(t, "BDAT 0", 250)

	deadline := time.Now().Add(time.Second)

	for len(srv.dataWork) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if len(srv.dataWork) != 1 {
		t.Fatal("BDAT did not acquire DATA worker")
	}

	// NOOP refreshes go-smtp's command deadline, but must not renew Data's timer.
	for range 3 {
		time.Sleep(250 * time.Millisecond)

		cl.cmd(t, "NOOP", 250)
	}

	time.Sleep(400 * time.Millisecond)

	cl.expectClosed(t)
	cl.close()

	deadline = time.Now().Add(time.Second)

	for len(srv.dataWork) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if len(srv.dataWork) != 0 {
		t.Fatal("DATA worker remained held after BDAT deadline")
	}

	cfg.Server.ReadTimeout = "5s"

	next := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer next.close()

	next.authPlain(t, "alice", password)

	beginMessage(t, next, "")
	writeMessage(next, "ordinary DATA after BDAT cleanup")

	next.readCode(t, 250)
}

func TestMalformedDataConsumesSubmissionBudget(t *testing.T) {
	const password = "malformed-rate-password"

	srv, _, _, _, pool := testServerWithUser(t, password)

	srv.rates = newSubmissionLimiter(2, 2, 2, 2)

	runTestSubmission(t, srv)

	cl := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer cl.close()

	cl.authPlain(t, "alice", password)

	cl.cmd(t, "MAIL FROM:<unauthorized@test.example>", 550)

	for range 2 {
		beginMessage(t, cl, "")

		_, _ = io.WriteString(cl.conn, "not-a-header\r\n\r\nbody\r\n.\r\n")

		cl.readCode(t, 550)
	}

	beginMessage(t, cl, "")

	cl.expectClosed(t)
}

func TestSigningAndQueueFailuresConsumeSubmissionBudget(t *testing.T) {
	const password = "failure-rate-password"

	srv, _, _, validSigner, pool := testServerWithUser(t, password)

	runTestSubmission(t, srv)

	cl := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer cl.close()

	cl.authPlain(t, "alice", password)

	srv.rates = newSubmissionLimiter(1, 1, 1, 1)
	srv.signer = new(sign.Signer)

	beginMessage(t, cl, "")
	writeMessage(cl, "sign failure")

	cl.readCode(t, 451)

	srv.signer = validSigner

	beginMessage(t, cl, "")

	cl.expectClosed(t)

	full, err := queue.Open(filepath.Join(t.TempDir(), "full-queue"), queue.Limits{MaxBytes: 1})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = full.Close()
	})

	originalQueue := srv.queue

	srv.queue = full
	srv.rates = newSubmissionLimiter(1, 1, 1, 1)

	queueClient := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer queueClient.close()

	queueClient.authPlain(t, "alice", password)

	beginMessage(t, queueClient, "")
	writeMessage(queueClient, "queue failure")

	queueClient.readCode(t, 452)

	srv.queue = originalQueue

	beginMessage(t, queueClient, "")

	queueClient.expectClosed(t)
}

func TestBody7BitAndReset(t *testing.T) {
	const password = "body-mode-password"

	srv, _, _, _, pool := testServerWithUser(t, password)

	runTestSubmission(t, srv)

	cl := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer cl.close()

	cl.authPlain(t, "alice", password)

	beginMessage(t, cl, "")
	writeMessage(cl, "caf\xc3\xa9")

	cl.readCode(t, 550)

	beginMessage(t, cl, "8BITMIME")
	writeMessage(cl, "caf\xc3\xa9")

	cl.readCode(t, 250)

	beginMessage(t, cl, "")
	writeMessage(cl, "latin-1 caf\xe9")

	cl.readCode(t, 550)

	beginMessage(t, cl, "8BITMIME")
	writeMessage(cl, "latin-1 caf\xe9")

	cl.readCode(t, 250)

	s := &session{body: smtp.Body7Bit, sender: "a@example.com", smtpUTF8: true}
	s.Reset()

	if s.body != "" || s.sender != "" || s.smtpUTF8 {
		t.Fatalf("Reset retained transaction state: body=%q sender=%q utf8=%v", s.body, s.sender, s.smtpUTF8)
	}
}

func TestOriginatorAuthorization(t *testing.T) {
	const password = "originator-password"

	srv, _, _, _, pool := testServerWithUser(t, password)

	runTestSubmission(t, srv)

	cl := dialSTARTTLS(t, srv.starttls.Addr, pool)
	defer cl.close()

	cl.authPlain(t, "alice", password)

	cl.cmd(t, "MAIL FROM:<alice.sender@test.example>", 550)
	cl.cmd(t, "MAIL FROM:<Alice.Sender@TEST.EXAMPLE>", 250)
	cl.cmd(t, "RSET", 250)

	for _, tt := range []originatorHeaderCase{
		{"case-mismatched From", "From: alice.sender@test.example\r\n"},
		{"unauthorized Sender", "Sender: attacker@test.example\r\n"},
		{"case-mismatched Sender", "Sender: ALICE@test.example\r\n"},
		{"unsupported Resent-From", "Resent-From: Alice.Sender@test.example\r\n"},
		{"unsupported Resent-Sender", "Resent-Sender: Alice.Sender@test.example\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			beginMessage(t, cl, "")

			from := "From: Alice.Sender@test.example\r\n"

			if strings.HasPrefix(tt.header, "From:") {
				from = ""
			}

			_, _ = io.WriteString(cl.conn, from+tt.header+"To: dest@example.com\r\n\r\nbody\r\n.\r\n")

			cl.readCode(t, 550)
		})
	}

	beginMessage(t, cl, "")

	_, _ = io.WriteString(cl.conn, "From: Alice.Sender@test.example\r\nSender: alice@test.example\r\nTo: dest@example.com\r\n\r\nbody\r\n.\r\n")

	cl.readCode(t, 250)
}

func TestPreAuthAbsoluteLifetimeAndAuthClearsDeadline(t *testing.T) {
	const password = "absolute-auth-password"

	t.Run("NOOP cannot extend", func(t *testing.T) {
		srv, cfg, _, _, _ := testServerWithUser(t, password)

		cfg.Server.ReadTimeout = "150ms"

		runTestSubmission(t, srv)

		conn, err := net.DialTimeout("tcp", srv.starttls.Addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}

		defer conn.Close()

		reader := bufio.NewReader(conn)

		_, err = reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}

		deadline := time.Now().Add(time.Second)

		for time.Now().Before(deadline) {
			time.Sleep(35 * time.Millisecond)

			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

			_, err = io.WriteString(conn, "NOOP\r\n")
			if err != nil {
				return
			}

			_, err = reader.ReadString('\n')
			if err != nil {
				return
			}
		}

		t.Fatal("periodic NOOP extended the pre-auth lifetime")
	})

	t.Run("successful auth clears", func(t *testing.T) {
		srv, cfg, _, _, pool := testServerWithUser(t, password)

		cfg.Server.ReadTimeout = "1s"

		const username = "ali\t\"ce"

		alice, ok := cfg.User("alice")
		if !ok {
			t.Fatal("test user missing")
		}

		err := cfg.AddUser(config.User{
			Username:       username,
			PasswordHash:   alice.PasswordHash,
			AllowedSenders: []string{"alice@test.example"},
			Enabled:        true,
		})

		if err != nil {
			t.Fatal(err)
		}

		logs := new(captureLog)

		srv.log = logs
		srv.starttls.ErrorLog = logs

		runTestSubmission(t, srv)

		cl := dialSTARTTLS(t, srv.starttls.Addr, pool)
		defer cl.close()

		cl.authPlain(t, username, password)

		time.Sleep(1100 * time.Millisecond)

		cl.cmd(t, "NOOP", 250)

		if !strings.Contains(logs.String(), `authenticated user "ali\t\"ce" from "127.0.0.1"`) {
			t.Fatalf("missing safely quoted acceptance log: %q", logs.String())
		}
	})
}

func TestDataDeadlineQueueAddOutcomes(t *testing.T) {
	for _, tt := range []dataDeadlineQueueAddCase{
		{"durably accepted before deadline return", nil, true},
		{"precommit error after deadline", errors.New("injected queue failure"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const password = "data-context-password"

			srv, cfg, spool, _, pool := testServerWithUser(t, password)

			cfg.Server.ReadTimeout = "5s"

			srv.dataWork = make(chan struct{}, 1)

			logs := new(captureLog)

			srv.log = logs
			srv.starttls.ErrorLog = logs

			entered := make(chan struct{})
			expired := make(chan struct{})
			release := make(chan struct{})

			var called atomic.Int32

			add := srv.queueAdd

			srv.queueAdd = func(ctx context.Context, envelope *queue.Envelope, data []byte) error {
				called.Add(1)

				if tt.accepted {
					err := add(ctx, envelope, data)
					if err != nil {
						return err
					}
				}

				close(entered)
				<-ctx.Done()

				close(expired)
				<-release

				return tt.err
			}

			runTestSubmission(t, srv)

			cl := dialSTARTTLS(t, srv.starttls.Addr, pool)

			cl.authPlain(t, "alice", password)

			beginMessage(t, cl, "")
			writeMessage(cl, "queue operation outlives DATA deadline")

			awaitCh(t, entered, 10*time.Second, "queue add")
			awaitCh(t, expired, 10*time.Second, "DATA deadline")

			close(release)

			cl.expectClosed(t)
			cl.close()

			deadline := time.Now().Add(time.Second)

			for len(srv.dataWork) != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}

			if len(srv.dataWork) != 0 {
				t.Fatal("DATA worker remained held after queue add returned")
			}

			if called.Load() != 1 {
				t.Fatalf("queue seam calls=%d want 1", called.Load())
			}

			if got := spool.Len(); got != map[bool]int{true: 1, false: 0}[tt.accepted] {
				t.Fatalf("queue length=%d accepted=%v", got, tt.accepted)
			}

			queued := strings.Contains(logs.String(), "queued ")
			if queued != tt.accepted {
				t.Fatalf("queued log=%v accepted=%v logs=%q", queued, tt.accepted, logs.String())
			}
		})
	}
}

func TestDataDeadlineDuringSigningPreventsQueueAdd(t *testing.T) {
	const password = "data-sign-context-password"

	srv, cfg, spool, _, pool := testServerWithUser(t, password)

	cfg.Server.ReadTimeout = "100ms"

	srv.dataWork = make(chan struct{}, 1)

	var signed, added atomic.Int32

	srv.signMessage = func(ctx context.Context, data []byte) (string, error) {
		signed.Add(1)
		<-ctx.Done()

		return "", ctx.Err()
	}

	srv.queueAdd = func(ctx context.Context, envelope *queue.Envelope, data []byte) error {
		added.Add(1)

		return errors.New("queue add must not run")
	}

	runTestSubmission(t, srv)

	cl := dialSTARTTLS(t, srv.starttls.Addr, pool)

	cl.authPlain(t, "alice", password)

	beginMessage(t, cl, "")
	writeMessage(cl, "signing waits for cancellation")

	cl.expectClosed(t)
	cl.close()

	if signed.Load() != 1 || added.Load() != 0 {
		t.Fatalf("sign calls=%d queue calls=%d", signed.Load(), added.Load())
	}

	if spool.Len() != 0 {
		t.Fatalf("timed-out signing committed %d messages", spool.Len())
	}

	deadline := time.Now().Add(time.Second)

	for len(srv.dataWork) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if len(srv.dataWork) != 0 {
		t.Fatal("DATA worker remained held after signing timeout")
	}
}
