package deliver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coalaura/outboxd/internal/queue"
)

type groupKey struct {
	domain string
	body   int
}

func (d *Deliverer) attempt(ctx context.Context, envelope *queue.Envelope) error {
	owner := deliveryOwner(envelope)
	if !d.users.tryAcquire(owner) {
		d.debugf("delivery %s waiting %s for user capacity\n", envelope.ID, d.admission)

		envelope.NextAttempt = time.Now().Add(d.admission)

		err := d.queue.Retry(envelope)
		if err != nil {
			return fmt.Errorf("reschedule %s for user capacity: %w", envelope.ID, err)
		}

		return nil
	}

	domain := nextPendingDomain(envelope)
	if !d.domains.tryAcquire(domain) {
		d.users.release(owner)

		envelope.NextAttempt = time.Now().Add(d.admission)

		d.log.Printf("rescheduling %s for domain capacity in %s\n", envelope.ID, d.admission)

		err := d.queue.Retry(envelope)
		if err != nil {
			return fmt.Errorf("reschedule %s for domain capacity: %w", envelope.ID, err)
		}

		return nil
	}

	return d.attemptAdmitted(ctx, envelope, owner, domain)
}

func (d *Deliverer) attemptAdmitted(ctx context.Context, envelope *queue.Envelope, admittedOwner, admittedDomain string) error {
	defer d.users.release(admittedOwner)

	heldDomain := admittedDomain

	defer func() {
		if heldDomain != "" {
			d.domains.release(heldDomain)
		}
	}()

	if ctx.Err() != nil {
		d.queue.Requeue(envelope)

		return nil
	}

	expired, err := d.expire(envelope)
	if err != nil {
		return err
	}

	if expired {
		return nil
	}

	parentCtx := ctx
	lifetimeDeadline := envelope.Created.Add(d.lifetime)
	deadline := lifetimeDeadline
	deadlineCause := error(errLifetime)

	attemptDeadline := time.Now().Add(d.attemptTO)
	if attemptDeadline.Before(deadline) {
		deadline = attemptDeadline
		deadlineCause = errAttemptTimeout
	}

	ctx, cancel := context.WithDeadlineCause(ctx, deadline, deadlineCause)
	defer cancel()

	envelope.Attempts++
	envelope.LastError = ""

	trace := d.newDebugTrace()

	d.debugf("delivery %s attempt %d started: pending=%d\n", envelope.ID, envelope.Attempts, envelope.Pending())

	defer func() {
		d.debugf("delivery %s attempt %d finished: %s\n", envelope.ID, envelope.Attempts, trace)
	}()

	groups := make(map[groupKey][]int, len(envelope.Recipients))
	groupOrder := make([]groupKey, 0, len(envelope.Recipients))

	for i := range envelope.Recipients {
		recipient := &envelope.Recipients[i]
		if recipient.Status != queue.StatusPending {
			continue
		}

		key := groupKey{domain: recipient.Domain, body: recipient.Body}

		_, ok := groups[key]
		if !ok {
			groupOrder = append(groupOrder, key)
		}

		groups[key] = append(groups[key], i)
	}

	if admittedDomain != "" && len(groupOrder) > 1 && groupOrder[0].domain != admittedDomain {
		for i, key := range groupOrder[1:] {
			if key.domain != admittedDomain {
				continue
			}

			index := i + 1
			copy(groupOrder[1:index+1], groupOrder[:index])
			groupOrder[0] = key

			break
		}
	}

	envelope.PreferredDomain = ""

	diagnostics := make([]string, 0, len(groupOrder))
	blockedDomain := ""

	for _, key := range groupOrder {
		domain := key.domain

		indexes := groups[key]
		if ctx.Err() != nil {
			break
		}

		if heldDomain != domain {
			if !d.domains.tryAcquire(domain) {
				blockedDomain = domain

				break
			}

			heldDomain = domain
		}

		previousDetails := make([]string, len(indexes))

		for i, index := range indexes {
			previousDetails[i] = envelope.Recipients[index].Detail
		}

		err := d.domain(ctx, envelope, domain, key.body, indexes)

		d.domains.release(domain)

		heldDomain = ""

		if queue.IsCorruption(err) {
			return err
		}

		if ctx.Err() != nil {
			for i, index := range indexes {
				recipient := &envelope.Recipients[index]
				if recipient.Status == queue.StatusPending {
					recipient.Detail = previousDetails[i]
				}
			}

			break
		}

		if err != nil {
			detail := normalizeDiagnostic(fmt.Sprintf("%s: %s", domain, err))

			diagnostics = append(diagnostics, detail)

			for _, index := range indexes {
				recipient := &envelope.Recipients[index]
				if recipient.Status == queue.StatusPending && recipient.Detail == "" {
					recipient.Detail = detail
				}
			}
		}
	}

	outcomeCause := context.Cause(ctx)
	if outcomeCause == nil && !time.Now().Before(deadline) {
		outcomeCause = deadlineCause
	}

	if errors.Is(outcomeCause, errAttemptTimeout) {
		diagnostics = append(diagnostics, errAttemptTimeout.Error())
	}

	envelope.LastError = normalizeDiagnostic(strings.Join(diagnostics, "; "))

	switch {
	case envelope.Pending() == 0:
		return d.complete(envelope)
	case parentCtx.Err() != nil:
		envelope.Attempts--
		envelope.NextAttempt = time.Now()

		err = d.queue.Retry(envelope)
		if err != nil {
			return fmt.Errorf("retry canceled %s: %w", envelope.ID, err)
		}

		return nil
	case errors.Is(outcomeCause, errLifetime):
		return d.expirePending(envelope)
	case blockedDomain != "":
		envelope.NextAttempt = time.Now()

		err = d.queue.RetryDeferred(envelope)
		if err != nil {
			return fmt.Errorf("defer %s for domain capacity: %w", envelope.ID, err)
		}

		d.parkAdmission(envelope, admissionDomain, blockedDomain)

		return nil
	case envelope.Attempts >= d.cfg.Delivery.MaxAttempts:
		for i := range envelope.Recipients {
			recipient := &envelope.Recipients[i]
			if recipient.Status == queue.StatusPending {
				recipient.Status = queue.StatusFailed

				// Preserve the most useful diagnostic for DSN/dead-letter.
				switch {
				case recipient.Detail != "":
					// keep capability-specific or prior MX detail
				default:
					recipient.Detail = exhaustedDetail
				}

				recipient.Code = 554
				recipient.EnhancedCode = terminalEnhancedCode
			}
		}

		d.log.Printf("giving up on %s after %d attempts: %s\n", envelope.ID, envelope.Attempts, envelope.LastError)

		return d.failTerminal(envelope)
	default:
		envelope.NextAttempt = time.Now().Add(d.backoff(envelope.Attempts))

		deadline := envelope.Created.Add(d.lifetime)
		if deadline.Before(envelope.NextAttempt) {
			envelope.NextAttempt = deadline
		}

		d.log.Printf("retrying %s in %s: %s\n", envelope.ID, time.Until(envelope.NextAttempt).Round(time.Second), envelope.LastError)

		err = d.queue.Retry(envelope)
		if err != nil {
			return fmt.Errorf("retry %s: %w", envelope.ID, err)
		}

		return nil
	}
}
