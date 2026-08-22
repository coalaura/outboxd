package deliver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"
)

const bestEffortQuitTimeout = time.Second

// MailOpts controls MAIL FROM parameters.
type MailOpts struct {
	Size     int64
	UTF8     bool
	EightBit bool
}

// Client is an outbound SMTP submission client built on net/textproto.
type Client struct {
	conn        net.Conn
	text        *textproto.Conn
	ext         map[string]string
	tls         bool
	command     time.Duration
	submission  time.Duration
	bounded     *boundedResponseConn
	stopWatch   context.CancelFunc
	ctxDeadline time.Time
}

type dataWriter struct {
	client *Client
	w      io.WriteCloser
	closed bool
	reply  string
}

func (c *Client) bindContext(ctx context.Context) {
	watch, stop := context.WithCancel(context.Background())

	c.ctxDeadline, _ = ctx.Deadline()
	c.stopWatch = stop

	conn := c.conn

	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-watch.Done():
		}
	}()
}

func (c *Client) setDeadline(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	if !c.ctxDeadline.IsZero() && c.ctxDeadline.Before(deadline) {
		deadline = c.ctxDeadline
	}

	_ = c.conn.SetDeadline(deadline)
}

// Greet reads the server banner.
func (c *Client) Greet() error {
	c.setDeadline(c.command)
	defer c.conn.SetDeadline(time.Time{})

	c.bounded.reset()

	_, _, err := c.readResponse(220)
	return err
}

// EHLO sends EHLO with the given hostname and records extensions.
func (c *Client) EHLO(hostname string) error {
	c.setDeadline(c.command)
	defer c.conn.SetDeadline(time.Time{})

	id, err := c.text.Cmd("EHLO %s", hostname)
	if err != nil {
		return err
	}

	c.text.StartResponse(id)
	defer c.text.EndResponse(id)

	c.bounded.reset()

	_, lines, err := c.readResponseLines(250)
	if err != nil {
		return err
	}

	c.ext = parseExtensions(lines)
	return nil
}

// HELO sends the legacy greeting and clears ESMTP extensions.
func (c *Client) HELO(hostname string) error {
	c.setDeadline(c.command)
	defer c.conn.SetDeadline(time.Time{})

	err := c.cmd(250, "HELO %s", hostname)
	if err != nil {
		return err
	}

	c.ext = make(map[string]string)
	return nil
}

// Extension reports whether the peer advertised name.
func (c *Client) Extension(name string) (bool, string) {
	v, ok := c.ext[strings.ToUpper(name)]
	return ok, v
}

// StartTLS upgrades the connection. ServerName on cfg provides SNI.
func (c *Client) StartTLS(cfg *tls.Config) error {
	c.setDeadline(c.command)
	defer c.conn.SetDeadline(time.Time{})

	err := c.cmd(220, "STARTTLS")
	if err != nil {
		return err
	}

	tlsConn := tls.Client(c.conn, cfg)

	err = tlsConn.Handshake()
	if err != nil {
		return err
	}

	c.conn = tlsConn
	c.bounded = &boundedResponseConn{Conn: tlsConn}
	c.text = textproto.NewConn(c.bounded)
	c.tls = true
	c.ext = make(map[string]string)

	return nil
}

// TLS reports whether the session is encrypted.
func (c *Client) TLS() bool {
	return c.tls
}

// Mail issues MAIL FROM.
func (c *Client) Mail(from string, opts MailOpts) error {
	c.setDeadline(c.command)
	defer c.conn.SetDeadline(time.Time{})

	var b strings.Builder

	fmt.Fprintf(&b, "MAIL FROM:<%s>", from)

	if opts.EightBit {
		_, ok := c.ext["8BITMIME"]
		if !ok {
			return err8BITMIMEUnsupported
		}

		b.WriteString(" BODY=8BITMIME")
	}

	if opts.Size > 0 {
		_, ok := c.ext["SIZE"]
		if ok {
			fmt.Fprintf(&b, " SIZE=%d", opts.Size)
		}
	}

	if opts.UTF8 {
		_, ok := c.ext["SMTPUTF8"]
		if !ok {
			return errSMTPUTF8Unsupported
		}

		b.WriteString(" SMTPUTF8")
	}

	return c.cmd(250, "%s", b.String())
}

// Rcpt issues RCPT TO.
func (c *Client) Rcpt(to string) error {
	c.setDeadline(c.command)
	defer c.conn.SetDeadline(time.Time{})

	// c.cmd(25, ...) accepts the 250 reply class (exact code may vary, e.g. 250/251).
	return c.cmd(25, "RCPT TO:<%s>", to)
}

// RcptBatch pipelines RCPT commands and returns the responses received in order.
// A transport error leaves recipients without a returned response indeterminate.
func (c *Client) RcptBatch(recipients []string) ([]error, error) {
	c.setDeadline(c.command)
	defer c.conn.SetDeadline(time.Time{})

	ids := make([]uint, 0, len(recipients))

	for _, recipient := range recipients {
		id, err := c.text.Cmd("RCPT TO:<%s>", recipient)
		if err != nil {
			return nil, err
		}

		ids = append(ids, id)
	}

	results := make([]error, 0, len(ids))

	for _, id := range ids {
		c.text.StartResponse(id)

		c.bounded.reset()

		_, _, err := c.readResponse(25)

		c.text.EndResponse(id)

		results = append(results, err)

		if err != nil && smtpCode(err) == 0 {
			return results, err
		}
	}

	return results, nil
}

// Data starts the DATA phase; Close on the writer finalizes and reads the reply.
func (c *Client) Data() (*dataWriter, error) {
	c.setDeadline(c.command)

	err := c.cmd(354, "DATA")
	if err != nil {
		c.conn.SetDeadline(time.Time{})

		return nil, err
	}

	c.setDeadline(c.submission)

	return &dataWriter{client: c, w: c.text.DotWriter()}, nil
}

// Quit sends QUIT as a best effort and closes without waiting for the reply.
func (c *Client) Quit() error {
	c.setDeadline(min(c.command, bestEffortQuitTimeout))
	defer c.conn.SetDeadline(time.Time{})

	err := c.text.PrintfLine("QUIT")

	c.Close()

	return err
}

// Close aborts the connection.
func (c *Client) Close() error {
	if c.stopWatch != nil {
		c.stopWatch()
		c.stopWatch = nil
	}

	if c.text != nil {
		return c.text.Close()
	}

	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

func (d *dataWriter) Write(p []byte) (int, error) {
	return d.w.Write(p)
}

func (d *dataWriter) Close() error {
	if d.closed {
		return nil
	}

	d.closed = true

	err := d.w.Close()

	defer d.client.conn.SetDeadline(time.Time{})

	if err != nil {
		return err
	}

	d.client.bounded.reset()

	code, msg, rerr := d.client.readResponse(250)
	if rerr != nil {
		return rerr
	}

	d.reply = fmt.Sprintf("%d %s", code, msg)

	return nil
}

// Reply returns the DATA acceptance line after Close.
func (d *dataWriter) Reply() string {
	return d.reply
}

func (c *Client) cmd(expect int, format string, args ...any) error {
	id, err := c.text.Cmd(format, args...)
	if err != nil {
		return err
	}

	c.text.StartResponse(id)
	defer c.text.EndResponse(id)

	c.bounded.reset()

	_, _, err = c.readResponse(expect)
	return err
}

// NewClient wraps an established connection after dial; call Greet next.
func NewClient(conn net.Conn, command, submission time.Duration) *Client {
	if command <= 0 {
		command = 5 * time.Minute
	}

	if submission <= 0 {
		submission = 12 * time.Minute
	}

	bounded := &boundedResponseConn{Conn: conn}

	return &Client{
		conn:       conn,
		text:       textproto.NewConn(bounded),
		ext:        make(map[string]string),
		command:    command,
		submission: submission,
		bounded:    bounded,
	}
}
