package deliver

import (
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	maxSMTPResponseBytes = 64 << 10
	maxDiagnosticBytes   = 1024
	maxResponseRead      = 1024
)

// SMTPError is a negative SMTP reply.
type SMTPError struct {
	Code         int
	EnhancedCode string
	Message      string
}

// boundedResponseConn limits one SMTP reply and caps buffered read-ahead.
type boundedResponseConn struct {
	net.Conn
	mu        sync.Mutex
	remaining int
	exceeded  bool
}

var errSMTPResponseTooLarge = errors.New("SMTP response exceeds size limit")

func (e *SMTPError) Error() string {
	return fmt.Sprintf("%d %s", e.Code, e.Message)
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
	if se, ok := errors.AsType[*SMTPError](err); ok {
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
