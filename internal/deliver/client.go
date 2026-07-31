package deliver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// SMTPError is a negative SMTP reply.
type SMTPError struct {
	Code    int
	Message string
}

func (e *SMTPError) Error() string {
	return fmt.Sprintf("%d %s", e.Code, e.Message)
}

// MailOpts controls MAIL FROM parameters.
type MailOpts struct {
	Size     int64
	UTF8     bool
	EightBit bool
}

// Client is an outbound SMTP submission client built on net/textproto.
type Client struct {
	conn       net.Conn
	text       *textproto.Conn
	ext        map[string]string
	tls        bool
	command    time.Duration
	submission time.Duration
}

// NewClient wraps an established connection after dial; call Greet next.
func NewClient(conn net.Conn, command, submission time.Duration) *Client {
	if command <= 0 {
		command = 5 * time.Minute
	}
	if submission <= 0 {
		submission = 12 * time.Minute
	}
	return &Client{
		conn:       conn,
		text:       textproto.NewConn(conn),
		ext:        make(map[string]string),
		command:    command,
		submission: submission,
	}
}

// Greet reads the server banner.
func (c *Client) Greet() error {
	c.conn.SetDeadline(time.Now().Add(c.command))
	defer c.conn.SetDeadline(time.Time{})

	_, _, err := c.readResponse(220)
	return err
}

// EHLO sends EHLO with the given hostname and records extensions.
func (c *Client) EHLO(hostname string) error {
	c.conn.SetDeadline(time.Now().Add(c.command))
	defer c.conn.SetDeadline(time.Time{})

	id, err := c.text.Cmd("EHLO %s", hostname)
	if err != nil {
		return err
	}
	c.text.StartResponse(id)
	defer c.text.EndResponse(id)

	_, lines, err := c.readResponseLines(250)
	if err != nil {
		return err
	}
	c.ext = parseExtensions(lines)
	return nil
}

// Extension reports whether the peer advertised name.
func (c *Client) Extension(name string) (bool, string) {
	v, ok := c.ext[strings.ToUpper(name)]
	return ok, v
}

// StartTLS upgrades the connection. ServerName on cfg provides SNI.
func (c *Client) StartTLS(cfg *tls.Config) error {
	c.conn.SetDeadline(time.Now().Add(c.command))
	defer c.conn.SetDeadline(time.Time{})

	if err := c.cmd(220, "STARTTLS"); err != nil {
		return err
	}

	tlsConn := tls.Client(c.conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	c.conn = tlsConn
	c.text = textproto.NewConn(tlsConn)
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
	c.conn.SetDeadline(time.Now().Add(c.command))
	defer c.conn.SetDeadline(time.Time{})

	var b strings.Builder
	fmt.Fprintf(&b, "MAIL FROM:<%s>", from)
	if opts.EightBit {
		if _, ok := c.ext["8BITMIME"]; !ok {
			return err8BITMIMEUnsupported
		}
		b.WriteString(" BODY=8BITMIME")
	}
	if opts.Size > 0 {
		if _, ok := c.ext["SIZE"]; ok {
			fmt.Fprintf(&b, " SIZE=%d", opts.Size)
		}
	}
	if opts.UTF8 {
		if _, ok := c.ext["SMTPUTF8"]; !ok {
			return errSMTPUTF8Unsupported
		}
		b.WriteString(" SMTPUTF8")
	}
	return c.cmd(250, "%s", b.String())
}

// Rcpt issues RCPT TO.
func (c *Client) Rcpt(to string) error {
	c.conn.SetDeadline(time.Now().Add(c.command))
	defer c.conn.SetDeadline(time.Time{})

	// c.cmd(25, ...) accepts the 250 reply class (exact code may vary, e.g. 250/251).
	return c.cmd(25, "RCPT TO:<%s>", to)
}

// Data starts the DATA phase; Close on the writer finalizes and reads the reply.
func (c *Client) Data() (*dataWriter, error) {
	c.conn.SetDeadline(time.Now().Add(c.command))

	if err := c.cmd(354, "DATA"); err != nil {
		c.conn.SetDeadline(time.Time{})
		return nil, err
	}
	c.conn.SetDeadline(time.Now().Add(c.submission))
	return &dataWriter{client: c, w: c.text.DotWriter()}, nil
}

// Quit sends QUIT.
func (c *Client) Quit() error {
	c.conn.SetDeadline(time.Now().Add(c.command))
	defer c.conn.SetDeadline(time.Time{})
	err := c.cmd(221, "QUIT")
	c.Close()
	return err
}

// Close aborts the connection.
func (c *Client) Close() error {
	if c.text != nil {
		return c.text.Close()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

type dataWriter struct {
	client *Client
	w      io.WriteCloser
	closed bool
	reply  string
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
	d.client.conn.SetDeadline(time.Now().Add(d.client.command))
	defer d.client.conn.SetDeadline(time.Time{})
	if err != nil {
		return err
	}
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
	_, _, err = c.readResponse(expect)
	return err
}

func (c *Client) readResponse(expect int) (int, string, error) {
	code, lines, err := c.readResponseLines(expect)
	if err != nil {
		return code, "", err
	}
	return code, strings.Join(lines, "\n"), nil
}

func (c *Client) readResponseLines(expect int) (int, []string, error) {
	code, msg, err := c.text.ReadResponse(expect)
	if err != nil {
		if tpErr, ok := err.(*textproto.Error); ok {
			return tpErr.Code, nil, &SMTPError{Code: tpErr.Code, Message: tpErr.Msg}
		}
		if code != 0 {
			return code, nil, &SMTPError{Code: code, Message: msg}
		}
		return code, nil, err
	}
	lines := strings.Split(msg, "\n")
	return code, lines, nil
}

func parseExtensions(lines []string) map[string]string {
	ext := make(map[string]string)
	// First line is the greeting line of the 250 response (hostname); extensions follow.
	for i, line := range lines {
		if i == 0 {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, param, _ := strings.Cut(line, " ")
		ext[strings.ToUpper(name)] = param
	}
	return ext
}

func smtpCode(err error) int {
	var se *SMTPError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

func permanent(err error) bool {
	code := smtpCode(err)
	return code >= 500 && code < 600
}

func describe(err error) string {
	var se *SMTPError
	if errors.As(err, &se) {
		return fmt.Sprintf("%d %s", se.Code, strings.TrimSpace(se.Message))
	}
	return err.Error()
}
