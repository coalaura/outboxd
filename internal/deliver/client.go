package deliver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxSMTPResponseBytes = 64 << 10
	maxDiagnosticBytes   = 1024
	maxResponseRead      = 1024
)

var errSMTPResponseTooLarge = errors.New("SMTP response exceeds size limit")

// SMTPError is a negative SMTP reply.
type SMTPError struct {
	Code         int
	EnhancedCode string
	Message      string
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

// boundedResponseConn limits one SMTP reply and caps buffered read-ahead.
type boundedResponseConn struct {
	net.Conn
	mu        sync.Mutex
	remaining int
	exceeded  bool
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

// Quit sends QUIT.
func (c *Client) Quit() error {
	c.setDeadline(c.command)
	defer c.conn.SetDeadline(time.Time{})

	err := c.cmd(221, "QUIT")

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

func (c *Client) readResponse(expect int) (int, string, error) {
	code, lines, err := c.readResponseLines(expect)
	if err != nil {
		return code, "", err
	}

	return code, strings.Join(lines, "\n"), nil
}

func (c *Client) readResponseLines(expect int) (int, []string, error) {
	code, msg, err := c.text.ReadResponse(expect)
	if c.bounded.exceededLimit() {
		return code, nil, errSMTPResponseTooLarge
	}

	if err != nil {
		tpErr, ok := err.(*textproto.Error)
		if ok {
			msg := normalizeDiagnostic(tpErr.Msg)

			return tpErr.Code, nil, &SMTPError{Code: tpErr.Code, EnhancedCode: parseEnhancedCode(tpErr.Code, msg), Message: msg}
		}

		if code != 0 {
			msg = normalizeDiagnostic(msg)

			return code, nil, &SMTPError{Code: code, EnhancedCode: parseEnhancedCode(code, msg), Message: msg}
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
	if se, ok := errors.AsType[*SMTPError](err); ok {
		return se.Code
	}

	return 0
}

func smtpEnhancedCode(err error) string {
	var se *SMTPError

	if errors.As(err, &se) {
		return se.EnhancedCode
	}

	return ""
}

func parseEnhancedCode(code int, message string) string {
	field, _, _ := strings.Cut(strings.TrimSpace(message), " ")

	parts := strings.Split(field, ".")
	if len(parts) != 3 || len(parts[0]) != 1 || parts[0][0] < '2' || parts[0][0] > '5' || int(parts[0][0]-'0') != code/100 {
		return ""
	}

	if parts[0] != "2" && parts[0] != "4" && parts[0] != "5" {
		return ""
	}

	for _, part := range parts[1:] {
		if len(part) < 1 || len(part) > 3 {
			return ""
		}

		for i := range len(part) {
			if part[i] < '0' || part[i] > '9' {
				return ""
			}
		}
	}

	return field
}

func permanent(err error) bool {
	code := smtpCode(err)
	return code >= 500 && code < 600
}

func describe(err error) string {
	if se, ok := errors.AsType[*SMTPError](err); ok {
		return normalizeDiagnostic(fmt.Sprintf("%d %s", se.Code, se.Message))
	}

	return normalizeDiagnostic(err.Error())
}

func (c *boundedResponseConn) reset() {
	c.mu.Lock()

	// Keep one probe byte so a reply of exactly maxSMTPResponseBytes is valid.
	c.remaining = maxSMTPResponseBytes + 1
	c.exceeded = false
	c.mu.Unlock()
}

func (c *boundedResponseConn) exceededLimit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.exceeded
}

func (c *boundedResponseConn) Read(p []byte) (int, error) {
	c.mu.Lock()

	if c.remaining <= 0 {
		c.mu.Unlock()
		return 0, errSMTPResponseTooLarge
	}

	limit := min(len(p), c.remaining, maxResponseRead)
	c.mu.Unlock()

	n, err := c.Conn.Read(p[:limit])

	c.mu.Lock()
	c.remaining -= n

	exhausted := c.remaining == 0
	if exhausted {
		c.exceeded = true
	}

	c.mu.Unlock()

	if err == nil && exhausted {
		return n, errSMTPResponseTooLarge
	}

	return n, err
}

func normalizeDiagnostic(s string) string {
	s = strings.ToValidUTF8(s, "�")

	var b strings.Builder
	b.Grow(min(len(s), maxDiagnosticBytes))

	var space bool

	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			space = true

			continue
		}

		if space && b.Len() > 0 && b.Len() < maxDiagnosticBytes {
			b.WriteByte(' ')
		}

		space = false

		if b.Len()+utf8.RuneLen(r) > maxDiagnosticBytes {
			break
		}

		b.WriteRune(r)
	}

	return strings.TrimSpace(b.String())
}
