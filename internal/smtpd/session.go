package smtpd

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/coalaura/outboxd/internal/config"
	"github.com/coalaura/outboxd/internal/mailbox"
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
	smtpUTF8   bool
	body       smtp.BodyType
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

	s.recipients = append(s.recipients, address)

	return nil
}

func (s *session) Data(r io.Reader) error {
	// go-smtp starts Data on the first BDAT chunk. Its per-command deadline can
	// be renewed by later commands, so independently bound the whole Data call.
	conn := s.conn.Conn()
	timer := time.AfterFunc(s.server.dataTimeout(), func() { _ = conn.Close() })
	defer timer.Stop()

	if s.sender == "" || len(s.recipients) == 0 {
		return &smtp.SMTPError{
			Code:         503,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "No valid recipients",
		}
	}

	if !s.server.acquireDataSlot() {
		return s.abortData(errDataBusy)
	}

	defer s.server.releaseDataSlot()

	// Rate is work admission: once admitted, all DATA processing outcomes consume it.
	if !s.server.rates.take(s.user.Username, len(s.recipients)) {
		s.server.log.Printf("rate-limited submission for user %q\n", s.user.Username)

		return s.abortData(errSubmissionRate)
	}

	var remoteAddress string

	if s.server.cfg.Server.IncludeClientIPInReceived {
		remoteAddress = host(s.conn)
	}

	maxBytes := s.server.cfg.Server.MaxMessageBytes
	body := io.Reader(r)
	if maxBytes > 0 {
		body = io.LimitReader(r, incrementLimit(maxBytes))
	}

	prepared, err := message.Prepare(body, message.Options{
		Hostname: s.server.cfg.Server.Hostname,
		Helo:     s.conn.Hostname(),
		Remote:   remoteAddress,
		TLS:      s.tls(),
		MaxBytes: maxBytes,
	})

	if err != nil {
		if errors.Is(err, message.ErrOversized) || errors.Is(err, smtp.ErrDataTooLarge) {
			return &smtp.SMTPError{
				Code:         552,
				EnhancedCode: smtp.EnhancedCode{5, 3, 4},
				Message:      "Message too large",
			}
		}

		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 0},
			Message:      responseText(err.Error()),
		}
	}

	if s.body == smtp.Body7Bit && prepared.EightBit {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 3},
			Message:      "BODY=7BIT message contains 8-bit data",
		}
	}

	if prepared.NeedsUTF8 && !s.smtpUTF8 {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 7},
			Message:      "SMTPUTF8 required for this message",
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

		return errTemporaryFailure
	}

	data := make([]byte, 0, len(signature)+len(prepared.Data))
	data = append(data, signature...)
	data = append(data, prepared.Data...)

	// Stored requirement is based on actual envelope/header needs, not client opt-in alone.
	needUTF8 := prepared.NeedsUTF8 || needsUTF8(s.sender)

	for _, rcpt := range s.recipients {
		if needsUTF8(rcpt) {
			needUTF8 = true
			break
		}
	}

	envelope := &queue.Envelope{
		ID:          identifier(),
		Username:    s.user.Username,
		Sender:      s.sender,
		Recipients:  make([]queue.Recipient, 0, len(s.recipients)),
		Created:     time.Now(),
		NextAttempt: time.Now(),
		SMTPUTF8:    needUTF8,
		EightBit:    prepared.EightBit,
	}

	for _, recipient := range s.recipients {
		domain, derr := mailbox.DomainOf(recipient)
		if derr != nil {
			return &smtp.SMTPError{
				Code:         501,
				EnhancedCode: smtp.EnhancedCode{5, 1, 3},
				Message:      "Invalid recipient address",
			}
		}

		envelope.Recipients = append(envelope.Recipients, queue.Recipient{
			Address: recipient,
			Domain:  domain,
			Status:  queue.StatusPending,
		})
	}

	err = s.server.queue.Add(envelope, data)
	if err != nil {
		s.server.log.Printf("failed to queue message: %v\n", err)

		if errors.Is(err, queue.ErrQueueFull) || errors.Is(err, queue.ErrInsufficientDisk) {
			return errQueueFull
		}

		return errTemporaryFailure
	}

	s.server.log.Printf("queued %s from %s for %d recipient(s)\n", envelope.ID, s.sender, len(envelope.Recipients))

	return nil
}

// go-smtp calls Data only after 354 and unconditionally drains its reader after
// Data returns. Closing is the only supported way to reject admission without
// consuming an attacker-controlled body.
func (s *session) abortData(err error) error {
	_ = s.conn.Close()
	return err
}

func (s *session) Reset() {
	s.sender = ""
	s.recipients = s.recipients[:0]
	s.smtpUTF8 = false
	s.body = ""
}

func (s *session) Logout() error {
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
		passwd.Waste()
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
