package deliver

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/coalaura/outboxd/internal/queue"
)

const (
	lifetimeDetail       = "maximum queue lifetime exceeded"
	exhaustedDetail      = "delivery attempts exhausted"
	terminalEnhancedCode = "5.4.7"
)

func (d *Deliverer) expire(envelope *queue.Envelope) (bool, error) {
	if time.Now().Before(envelope.Created.Add(d.lifetime)) {
		return false, nil
	}

	return true, d.expirePending(envelope)
}

func (d *Deliverer) expirePending(envelope *queue.Envelope) error {
	for i := range envelope.Recipients {
		recipient := &envelope.Recipients[i]

		if recipient.Status == queue.StatusPending {
			recipient.Status = queue.StatusFailed
			recipient.Detail = lifetimeDetail
			recipient.Code = 554
			recipient.EnhancedCode = terminalEnhancedCode
		}
	}

	envelope.LastError = lifetimeDetail

	d.log.Printf("expiring %s after %s\n", envelope.ID, d.lifetime)

	return d.failTerminal(envelope)
}

func (d *Deliverer) complete(envelope *queue.Envelope) error {
	var delivered, failed int

	for i := range envelope.Recipients {
		switch envelope.Recipients[i].Status {
		case queue.StatusSent:
			delivered++
		case queue.StatusFailed:
			failed++
		}
	}

	d.log.Printf("completed %s: %d delivered, %d failed\n", envelope.ID, delivered, failed)

	// All-recipient permanent failure → dead-letter with preserved diagnostics.
	if delivered == 0 && failed > 0 {
		return d.failTerminal(envelope)
	}

	err := d.ensureDSN(envelope)
	if err != nil {
		return fmt.Errorf("dsn %s: %w", envelope.ID, err)
	}

	err = d.queue.Finish(envelope)
	if err != nil {
		if errors.Is(err, queue.ErrCleanup) {
			d.log.Printf("finished %s with deferred cleanup: %s\n", envelope.ID, err)

			return nil
		}

		return fmt.Errorf("finish %s: %w", envelope.ID, err)
	}

	return nil
}

func (d *Deliverer) failTerminal(envelope *queue.Envelope) error {
	err := d.ensureDSN(envelope)
	if err != nil {
		return fmt.Errorf("dsn %s: %w", envelope.ID, err)
	}

	err = d.queue.Bury(envelope)
	if err != nil {
		return fmt.Errorf("bury %s: %w", envelope.ID, err)
	}

	return nil
}

func (d *Deliverer) reject(envelope *queue.Envelope, indexes []int, detail string) {
	detail = normalizeDiagnostic(detail)

	for _, index := range indexes {
		recipient := &envelope.Recipients[index]
		recipient.Status = queue.StatusFailed
		recipient.Detail = detail
	}
}

func (d *Deliverer) rejectSMTP(envelope *queue.Envelope, indexes []int, err error) {
	detail := describe(err)
	code := smtpCode(err)
	enhanced := smtpEnhancedCode(err)

	for _, index := range indexes {
		recipient := &envelope.Recipients[index]
		recipient.Status = queue.StatusFailed
		recipient.Detail = detail
		recipient.Code = code
		recipient.EnhancedCode = enhanced
	}
}

func (d *Deliverer) backoff(attempts int) time.Duration {
	delay := d.initial

	for range attempts - 1 {
		if delay >= d.maximum || delay > d.maximum/2 {
			delay = d.maximum
			break
		}

		delay *= 2
	}

	spread := int64(delay / 5)
	if spread <= 0 {
		return delay
	}

	delta := time.Duration(rand.Int64N(spread)) - delay/10
	if delta > 0 && delay > d.maximum-delta {
		return d.maximum
	}

	delay += delta
	if delay > d.maximum {
		return d.maximum
	}

	return delay
}
