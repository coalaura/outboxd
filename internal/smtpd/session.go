package smtpd

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/mailbox"
	"github.com/coalaura/outboxd/internal/passwd"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type session struct {
	server *Server
	conn   *smtp.Conn

	user         config.User
	sender       string
	recipients   []string
	smtpUTF8     bool
	body         smtp.BodyType
	authDeadline *authDeadlineConn

	dataDeadlineMu     sync.Mutex
	dataDeadlineCtx    context.Context
	dataDeadlineCancel context.CancelFunc
	dataDeadlineStop   func() bool
	dataDeadlineDone   chan struct{}
}

func (s *session) AuthMechanisms() []string {
	return []string{sasl.Plain, mechLogin}
}

func (s *session) Auth(mech string) (sasl.Server, error) {
	if !s.secure() {
		return nil, smtp.ErrAuthUnsupported
	}

	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			if identity != "" && identity != username {
				return smtp.ErrAuthFailed
			}

			return s.authenticate(username, password)
		}), nil
	case mechLogin:
		return newLoginServer(s.authenticate), nil
	}

	return nil, smtp.ErrAuthUnknownMechanism
}

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	if s.user.Username == "" {
		return smtp.ErrAuthRequired
	}

	address, err := address(from)
	if err != nil {
		return &smtp.SMTPError{
			Code:         501,
			EnhancedCode: smtp.EnhancedCode{5, 1, 7},
			Message:      "Invalid sender address",
		}
	}

	utf8Wanted := opts != nil && opts.UTF8
	if needsUTF8(address) && !utf8Wanted {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 7},
			Message:      "SMTPUTF8 required for this sender address",
		}
	}

	if !s.user.Allows(address) {
		s.server.log.Printf("rejected sender %q for user %q\n", address, s.user.Username)

		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Sender address not allowed for this account",
		}
	}

	if opts != nil && opts.Size > s.server.cfg.Server.MaxMessageBytes {
		return &smtp.SMTPError{
			Code:         552,
			EnhancedCode: smtp.EnhancedCode{5, 3, 4},
			Message:      "Message too large",
		}
	}

	s.sender = address
	s.recipients = s.recipients[:0]
	s.smtpUTF8 = utf8Wanted
	s.body = smtp.Body7Bit

	if opts != nil {
		if opts.Body != "" {
			s.body = opts.Body
		}
	}

	return nil
}

func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if s.sender == "" {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "MAIL FROM required first",
		}
	}

	address, err := address(to)

	var routing string

	if err == nil {
		if strings.HasPrefix(address[strings.LastIndexByte(address, '@')+1:], "[") {
			err = errors.New("literal address")
		} else {
			routing, err = mailbox.DomainOf(address)
		}
	}

	if err != nil || routing == "" {
		return &smtp.SMTPError{
			Code:         501,
			EnhancedCode: smtp.EnhancedCode{5, 1, 3},
			Message:      "Invalid recipient address",
		}
	}

	if needsUTF8(address) && !s.smtpUTF8 {
		return &smtp.SMTPError{
			Code:         553,
			EnhancedCode: smtp.EnhancedCode{5, 6, 7},
			Message:      "SMTPUTF8 required for this recipient address",
		}
	}

	// RFC 5321 lets a client repeat a recipient.
	if slices.Contains(s.recipients, address) {
		return nil
	}

	if len(s.recipients) == s.server.cfg.Server.MaxRecipients {
		return errTooManyRecipients
	}

	s.recipients = append(s.recipients, address)

	return nil
}

func (s *session) Reset() {
	s.clearDataDeadline()

	s.sender = ""
	s.recipients = s.recipients[:0]
	s.smtpUTF8 = false
	s.body = ""
}

func (s *session) Logout() error {
	s.clearDataDeadline()

	return nil
}

func (s *session) authenticate(username, password string) error {
	ip := host(s.conn)

	if !s.server.acquireHashSlot() {
		s.server.log.Printf("authentication busy from %s\n", ip)

		return errAuthBusy
	}

	defer s.server.releaseHashSlot()

	if !s.server.authLimit.reserve(ip, username) {
		s.server.log.Printf("throttled authentication from %s user %q\n", ip, username)

		return smtp.ErrAuthFailed
	}

	user, ok := s.server.cfg.User(username)
	if !ok || !user.Enabled {
		passwd.Waste(password)

		s.server.authLimit.failed(ip, username)

		return smtp.ErrAuthFailed
	}

	valid, err := passwd.Verify(user.PasswordHash, password)
	if err != nil {
		s.server.log.Printf("user %q has an unusable password hash: %v\n", user.Username, err)
	}

	if !valid {
		s.server.authLimit.failed(ip, username)

		return smtp.ErrAuthFailed
	}

	s.server.authLimit.succeeded(ip, username)

	s.user = user

	if s.authDeadline != nil {
		s.authDeadline.clear()
	}

	s.server.log.Printf("authenticated user %q from %q\n", user.Username, ip)

	return nil
}

func (s *session) secure() bool {
	_, ok := s.conn.TLSConnectionState()

	return ok
}

func (s *session) tls() string {
	state, ok := s.conn.TLSConnectionState()
	if !ok {
		return ""
	}

	return fmt.Sprintf("TLS%x", state.Version)
}
