package smtpd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coalaura/outboxd/internal/certs"
	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/passwd"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/coalaura/outboxd/internal/sign"
)

// testServerWithUser builds a submission stack with one Argon2id user and DKIM.
func testServerWithUser(t *testing.T, password string) (*Server, *config.Config, *queue.Queue, *sign.Signer, *x509.CertPool) {
	t.Helper()
	base := t.TempDir()
	cfgPath := filepath.Join(base, "config.yml")
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
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
		"  auth_queue: 8",
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
	if err := os.WriteFile(cfgPath, []byte(body), 0600); err != nil {
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
	if err := cfg.AddUser(config.User{
		Username:       "alice",
		PasswordHash:   hash,
		Enabled:        true,
		AllowedSenders: []string{"Alice.Sender@test.example", "alice@test.example"},
	}); err != nil {
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
	srv := New(cfg, k, signer, spool, testLog{})
	if err := srv.Listen(); err != nil {
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
	if err := tlsConn.Handshake(); err != nil {
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
		code := 0
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

func (c *smtpClient) authPlain(t *testing.T, user, pass string) {
	t.Helper()
	payload := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pass))
	c.cmd(t, "AUTH PLAIN "+payload, 235)
}

func (c *smtpClient) close() { _ = c.conn.Close() }

func TestSubmissionUnnecessarySMTPUTF8OptIn(t *testing.T) {
	const password = "test-password-xyz"
	srv, _, spool, _, pool := testServerWithUser(t, password)
	entered := waitServeEntered(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
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
