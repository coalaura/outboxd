package deliver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/queue"
)

const (
	storageRetryDelay          = 30 * time.Second
	defaultAdmissionRetryDelay = 30 * time.Second
)

// Run delivers queued messages until ctx is cancelled or a fatal queue error occurs.
func (d *Deliverer) Run(ctx context.Context) error {
	d.log.Printf("Delivery started with %d queued message(s)\n", d.queue.Len())

	// Registered first so it runs last: cancel() must fire before we wait.
	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	next := d.next
	if next == nil {
		next = d.queue.Next
	}

	for {
		err := d.fatalErr()
		if err != nil {
			cancel()
			wg.Wait()

			return err
		}

		envelope, err := next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				ferr := d.fatalErr()
				if ferr != nil {
					return ferr
				}

				return nil
			}

			return err
		}

		if ctx.Err() != nil {
			d.queue.Requeue(envelope)

			ferr := d.fatalErr()
			if ferr != nil {
				return ferr
			}

			return nil
		}

		admittedOwner := deliveryOwner(envelope)
		if !d.users.tryAcquire(admittedOwner) {
			d.queue.RequeueAfter(envelope, d.admission)

			continue
		}

		admittedDomain := nextPendingDomain(envelope)
		if !d.domains.tryAcquire(admittedDomain) {
			d.users.release(admittedOwner)

			// Admission is an in-memory scheduling decision, not a delivery attempt.
			d.queue.RequeueAfter(envelope, d.admission)

			continue
		}

		// Bound concurrent attempt goroutines after domain-aware admission.
		select {
		case d.active <- struct{}{}:
		case <-ctx.Done():
			d.domains.release(admittedDomain)
			d.users.release(admittedOwner)

			d.queue.Requeue(envelope)

			ferr := d.fatalErr()
			if ferr != nil {
				return ferr
			}

			return nil
		}

		wg.Go(func() {
			defer func() {
				<-d.active
			}()

			err := d.attemptAdmitted(ctx, envelope, admittedOwner, admittedDomain)
			if err != nil {
				if queue.IsCorruption(err) {
					quarantineErr := d.queue.QuarantineCheckedOut(envelope, err)
					if quarantineErr != nil {
						d.log.Printf("failed to quarantine corrupt queue item %s; item blocked: %s\n", envelope.ID, quarantineErr)

						if errors.Is(quarantineErr, queue.ErrIDConflict) {
							d.setFatal(fmt.Errorf("quarantine %s after %w failed with ambiguous identity: %w", envelope.ID, err, quarantineErr))

							cancel()
						}
					} else {
						d.log.Printf("quarantined corrupt queue item %s: %s\n", envelope.ID, err)
					}

					return
				}

				if queue.IsStoragePressure(err) {
					d.queue.RequeueAfter(envelope, storageRetryDelay)

					d.log.Printf("storage pressure handling %s; retrying queue state in %s: %s\n", envelope.ID, storageRetryDelay, err)

					return
				}

				d.setFatal(err)

				cancel()
			}
		})
	}
}

func (d *Deliverer) setFatal(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.fatal == nil {
		d.fatal = err
	}
}

func (d *Deliverer) fatalErr() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.fatal
}

func nextPendingDomain(envelope *queue.Envelope) string {
	for i := range envelope.Recipients {
		recipient := &envelope.Recipients[i]
		if recipient.Status == queue.StatusPending {
			return recipient.Domain
		}
	}

	return ""
}

func deliveryOwner(envelope *queue.Envelope) string {
	if envelope.DSNSourceID != "" {
		return generatedDSNOwner
	}

	return envelope.Username
}
