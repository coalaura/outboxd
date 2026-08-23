package smtpd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/coalaura/outboxd/internal/mailbox"
	"github.com/coalaura/outboxd/internal/message"
	"github.com/coalaura/outboxd/internal/openpgp"
	"github.com/coalaura/outboxd/internal/queue"
	"github.com/emersion/go-smtp"
)

func (s *session) Data(r io.Reader) error {
	// go-smtp starts Data on the first BDAT chunk. Its per-command deadline can
	// be renewed by later commands, so independently bound the whole Data call.
	ctx, cancel := context.WithTimeout(context.Background(), s.server.dataTimeout())

	conn := s.conn.Conn()

	closed := make(chan struct{})

	// Reset clears this callback only after go-smtp writes the final DATA/BDAT
	// response, so response delivery remains bounded by the same deadline.
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(closed)
	})

	s.dataDeadlineMu.Lock()
	s.dataDeadlineCtx = ctx
	s.dataDeadlineCancel = cancel
	s.dataDeadlineStop = stop
	s.dataDeadlineDone = closed
	s.dataDeadlineMu.Unlock()

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

	err := allowDataTerminator(r, maxBytes)
	if err != nil {
		s.server.log.Printf("go-smtp DATA reader compatibility failure: %v\n", err)

		return errTemporaryFailure
	}

	body := io.Reader(r)
	if maxBytes > 0 {
		body = io.LimitReader(r, incrementLimit(maxBytes))
	}

	prepared, err := message.PrepareContext(ctx, body, message.Options{
		Hostname: s.server.cfg.Server.Hostname,
		Helo:     s.conn.Hostname(),
		Remote:   remoteAddress,
		TLS:      s.tls(),
		MaxBytes: maxBytes,
	})

	if err != nil {
		if ctx.Err() != nil {
			s.waitDataDeadlineClose()

			return errTemporaryFailure
		}

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

	if prepared.Sender != "" && !s.user.Allows(prepared.Sender) {
		s.server.log.Printf("rejected Sender header %q for user %q\n", prepared.Sender, s.user.Username)

		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Sender header not allowed for this account",
		}
	}

	if err := ctx.Err(); err != nil {
		s.waitDataDeadlineClose()

		return errTemporaryFailure
	}

	var openPGPSigned bool

	prepared.Data, openPGPSigned, err = s.server.openPGPSign(ctx, prepared.From, prepared.Data)
	if err != nil {
		if ctx.Err() != nil {
			s.waitDataDeadlineClose()
		} else if errors.Is(err, openpgp.ErrMessageTooLarge) {
			return &smtp.SMTPError{
				Code:         552,
				EnhancedCode: smtp.EnhancedCode{5, 3, 4},
				Message:      "Message too large after OpenPGP signing",
			}
		}

		s.server.log.Printf("OpenPGP signing failed for %q: %v\n", prepared.From, err)

		return errTemporaryFailure
	}

	if openPGPSigned {
		prepared.EightBit = false
	}

	data, bodies, bodyIndexes, err := s.server.prepareVariants(ctx, prepared.Data, s.recipients, prepared.EightBit)
	if err != nil {
		if ctx.Err() != nil {
			s.waitDataDeadlineClose()
		} else if errors.Is(err, openpgp.ErrMessageTooLarge) {
			return &smtp.SMTPError{
				Code:         552,
				EnhancedCode: smtp.EnhancedCode{5, 3, 4},
				Message:      "Message too large after recipient encryption",
			}
		}

		s.server.log.Printf("recipient message preparation failed: %v\n", err)

		return errTemporaryFailure
	}

	// Stored requirement is based on actual envelope/header needs, not client opt-in alone.
	needUTF8 := prepared.NeedsUTF8 || needsUTF8(s.sender)

	if slices.ContainsFunc(s.recipients, needsUTF8) {
		needUTF8 = true
	}

	envelope := &queue.Envelope{
		ID:          identifier(),
		Username:    s.user.Username,
		Sender:      s.sender,
		Recipients:  make([]queue.Recipient, 0, len(s.recipients)),
		Created:     time.Now(),
		NextAttempt: time.Now(),
		SMTPUTF8:    needUTF8,
		EightBit:    bodies[0].EightBit,
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
			Body:    bodyIndexes[len(envelope.Recipients)],
			Status:  queue.StatusPending,
		})
	}

	if len(bodies) > 1 {
		envelope.Bodies = bodies
	}

	if err := ctx.Err(); err != nil {
		s.waitDataDeadlineClose()

		return errTemporaryFailure
	}

	err = s.server.queueAdd(ctx, envelope, data)
	if err == nil {
		if ctx.Err() != nil {
			s.waitDataDeadlineClose()
		}

		s.server.log.Printf("queued %s from %s for %d recipient(s)\n", envelope.ID, s.sender, len(envelope.Recipients))

		return nil
	}

	if ctx.Err() != nil {
		s.waitDataDeadlineClose()
	}

	s.server.log.Printf("failed to queue message: %v\n", err)

	if errors.Is(err, queue.ErrQueueFull) || errors.Is(err, queue.ErrInsufficientDisk) {
		return errQueueFull
	}

	return errTemporaryFailure
}

func (s *Server) prepareVariants(ctx context.Context, message []byte, recipients []string, eightBit bool) ([]byte, []queue.Body, []int, error) {
	variants := make(map[string]int, len(recipients))
	bodyIndexes := make([]int, len(recipients))
	bodies := make([]queue.Body, 0, len(recipients))
	bundle := make([]byte, 0, len(message))

	for index, recipient := range recipients {
		keyID, encrypted, err := s.openPGPRecipients.KeyID(recipient)
		if err != nil {
			return nil, nil, nil, err
		}

		variantKey := "plaintext"
		if encrypted {
			variantKey = "key:" + keyID
		}

		if bodyIndex, ok := variants[variantKey]; ok {
			bodyIndexes[index] = bodyIndex

			continue
		}

		variant := message
		variantEightBit := eightBit

		if encrypted {
			variant, encrypted, err = s.openPGPRecipients.Encrypt(ctx, recipient, keyID, message)
			if err != nil {
				return nil, nil, nil, err
			}
			if !encrypted {
				return nil, nil, nil, errors.New("recipient encryption key disappeared")
			}

			variantEightBit = false
		}

		signature, err := s.signMessage(ctx, variant)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("dkim signing: %w", err)
		}

		variant = append([]byte(signature), variant...)

		if len(bodies) != 0 && int64(len(bundle))+int64(len(variant)) > s.cfg.Server.MaxMessageBytes {
			return nil, nil, nil, fmt.Errorf("%w: all recipient variants exceed %d bytes", openpgp.ErrMessageTooLarge, s.cfg.Server.MaxMessageBytes)
		}

		bodyIndex := len(bodies)

		bodies = append(bodies, queue.NewBody(int64(len(bundle)), variant, variantEightBit))
		bundle = append(bundle, variant...)

		variants[variantKey] = bodyIndex
		bodyIndexes[index] = bodyIndex
	}

	return bundle, bodies, bodyIndexes, nil
}

func (s *session) waitDataDeadlineClose() {
	s.dataDeadlineMu.Lock()
	done := s.dataDeadlineDone
	s.dataDeadlineMu.Unlock()

	if done != nil {
		<-done
	}
}

// clearDataDeadline is called by go-smtp after its final response (or on
// logout), not when Data returns.
func (s *session) clearDataDeadline() {
	s.dataDeadlineMu.Lock()
	ctx := s.dataDeadlineCtx
	cancel := s.dataDeadlineCancel
	stop := s.dataDeadlineStop
	done := s.dataDeadlineDone

	s.dataDeadlineCtx = nil
	s.dataDeadlineCancel = nil
	s.dataDeadlineStop = nil
	s.dataDeadlineDone = nil
	s.dataDeadlineMu.Unlock()

	if stop == nil {
		return
	}

	expired := ctx.Err() != nil
	if !stop() {
		<-done
	} else if expired || ctx.Err() != nil {
		// Do not let response cleanup suppress a deadline that raced with Stop.
		_ = s.conn.Conn().Close()
	}

	cancel()
}

// go-smtp calls Data only after 354 and unconditionally drains its reader after
// Data returns. Closing is the only supported way to reject admission without
// consuming an attacker-controlled body.
func (s *session) abortData(err error) error {
	_ = s.conn.Close()

	return err
}
