package deliver

import (
	"context"
	"errors"

	"github.com/coalaura/outboxd/internal/queue"
)

func (d *Deliverer) domain(ctx context.Context, envelope *queue.Envelope, domain string, body int, indexes []int) error {
	trace := d.newDebugTrace()

	hosts, err := d.hosts(ctx, domain)

	trace.mark("mx_lookup")

	if err != nil {
		d.debugf("delivery %s MX lookup for %s failed: %s\n", envelope.ID, domain, trace)

		if errors.Is(err, errNullMX) || errors.Is(err, errNoSuchDomain) {
			d.reject(envelope, indexes, err.Error())

			return nil
		}

		return err
	}

	d.debugf("delivery %s MX lookup for %s returned %d host(s): %s\n", envelope.ID, domain, len(hosts), trace)

	var (
		last              error
		sawEligible       bool
		sawRetryable      bool
		capabilityOnly    = true
		sawUTF8CapErr     bool
		sawEightBitCapErr bool
	)

	for _, candidate := range hosts {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		host := candidate.host

		// Hold global only around MX I/O.
		trace = d.newDebugTrace()

		err = d.acquireGlobal(ctx)
		if err != nil {
			return err
		}

		trace.mark("global_wait")

		d.debugf("delivery %s acquired global capacity for %s: %s\n", envelope.ID, host, trace)

		done, err := d.send(ctx, envelope, candidate, body, indexes)

		d.releaseGlobal()

		if done {
			return nil
		}

		if err == nil {
			// send returned without completing or failing recipients permanently.
			capabilityOnly = false
			sawRetryable = true

			continue
		}

		sawEligible = true
		if errors.Is(err, errSMTPUTF8Unsupported) {
			sawUTF8CapErr = true
			if last == nil {
				last = err
			}

			continue
		}

		if errors.Is(err, err8BITMIMEUnsupported) {
			sawEightBitCapErr = true
			if last == nil {
				last = err
			}

			continue
		}

		// Any non-capability outcome means this is not a capability-only failure set.
		capabilityOnly = false
		if errors.Is(err, errPrivateDestination) {
			// Do not overwrite a prior retryable diagnostic with a private-destination
			// error; mixed outcomes must stay temporary (same class as capability mix).
			if last == nil {
				last = err
			}

			continue
		}

		sawRetryable = true
		last = err
	}

	if sawEligible && capabilityOnly && (sawUTF8CapErr || sawEightBitCapErr) {
		d.reject(envelope, indexes, capabilityDetail(sawUTF8CapErr, sawEightBitCapErr))

		return nil
	}

	if last != nil && !sawRetryable && errors.Is(last, errPrivateDestination) {
		d.reject(envelope, indexes, last.Error())

		return nil
	}

	if last == nil {
		last = errors.New("no usable MX host")
	}

	return last
}

func (d *Deliverer) acquireGlobal(ctx context.Context) error {
	select {
	case d.global <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Deliverer) releaseGlobal() {
	// Called only after a successful acquireGlobal.
	<-d.global
}

// capabilityDetail builds a permanent capability diagnostic without string-matching
// transient transport errors. When both requirements failed across candidates, both
// are reported.
func capabilityDetail(needUTF8, needEight bool) string {
	switch {
	case needUTF8 && needEight:
		return errSMTPUTF8Unsupported.Error() + "; " + err8BITMIMEUnsupported.Error()
	case needUTF8:
		return errSMTPUTF8Unsupported.Error()
	case needEight:
		return err8BITMIMEUnsupported.Error()
	default:
		return "required SMTP capability missing"
	}
}
