package smtpd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/message"
	"github.com/coalaura/outboxd/internal/passwd"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type session struct {
	server *Server
	conn   *smtp.Conn

	user       config.User
	sender     string
	recipients []string
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

	if !s.user.Allows(address) {
		s.server.log.Printf("rejected sender %q for user %q\n", address, s.user.Username)

		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Sender address not allowed for this account",
		}
	}

	s.sender = address
	s.recipients = s.recipients[:0]

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
	if err != nil || !strings.Contains(address[strings.LastIndexByte(address, '@')+1:], ".") {
		return &smtp.SMTPError{
			Code:         501,
			EnhancedCode: smtp.EnhancedCode{5, 1, 3},
			Message:      "Invalid recipient address",
		}
	}

	s.recipients = append(s.recipients, address)

	return nil
}

func (s *session) Data(r io.Reader) error {
	// go-smtp expects the reader to be consumed even on failure.
	defer io.Copy(io.Discard, r)

	if s.sender == "" || len(s.recipients) == 0 {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "No valid recipients",
		}
	}

	prepared, err := message.Prepare(r, message.Options{
		Hostname: s.server.cfg.Server.Hostname,
		Helo:     s.conn.Hostname(),
		Remote:   remote(s.conn),
		TLS:      s.tls(),
	})

	if err != nil {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 0},
			Message:      err.Error(),
		}
	}

	if !s.user.Allows(prepared.From) {
		s.server.log.Printf("rejected From header %q for user %q\n", prepared.From, s.user.Username)

		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "From header not allowed for this account",
		}
	}

	signature, err := s.server.signer.Signature(prepared.Data)
	if err != nil {
		s.server.log.Printf("dkim signing failed: %v\n", err)

		return temporaryFailureErr
	}

	data := make([]byte, 0, len(signature)+len(prepared.Data))
	data = append(data, signature...)
	data = append(data, prepared.Data...)

	envelope := &queue.Envelope{
		ID:          identifier(),
		Username:    s.user.Username,
		Sender:      s.sender,
		Recipients:  make([]queue.Recipient, 0, len(s.recipients)),
		Created:     time.Now(),
		NextAttempt: time.Now(),
	}

	for _, recipient := range s.recipients {
		envelope.Recipients = append(envelope.Recipients, queue.Recipient{
			Address: recipient,
			Domain:  recipient[strings.LastIndexByte(recipient, '@')+1:],
			Status:  queue.StatusPending,
		})
	}

	err = s.server.queue.Add(envelope, data)
	if err != nil {
		s.server.log.Printf("failed to queue message: %v\n", err)

		return temporaryFailureErr
	}

	s.server.log.Printf("queued %s from %s for %d recipient(s)\n", envelope.ID, s.sender, len(envelope.Recipients))

	return nil
}

func (s *session) Reset() {
	s.sender = ""
	s.recipients = s.recipients[:0]
}

func (s *session) Logout() error {
	return nil
}

func (s *session) authenticate(username, password string) error {
	ip := host(s.conn)

	if !s.server.limiter.allow(ip) {
		s.server.log.Printf("throttled authentication from %s\n", ip)

		return smtp.ErrAuthFailed
	}

	s.server.hashing <- struct{}{}
	defer func() { <-s.server.hashing }()

	user, ok := s.server.cfg.User(username)
	if !ok || !user.Enabled {
		passwd.Waste()
		s.server.limiter.failed(ip)

		return smtp.ErrAuthFailed
	}

	valid, err := passwd.Verify(user.PasswordHash, password)
	if err != nil {
		s.server.log.Printf("user %q has an unusable password hash: %v\n", user.Username, err)
	}

	if !valid {
		s.server.limiter.failed(ip)

		return smtp.ErrAuthFailed
	}

	s.server.limiter.succeeded(ip)
	s.user = user

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
