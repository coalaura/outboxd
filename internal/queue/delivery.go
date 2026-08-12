package queue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
)

// Next blocks until a message is due for delivery or ctx is cancelled.
// The returned envelope is removed from the in-memory schedule but remains on
// disk under ready/ until Finish, Retry, or Bury.
func (q *Queue) Next(ctx context.Context) (*Envelope, error) {
	err := q.beginOperation()
	if err != nil {
		return nil, err
	}

	defer q.endOperation()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	for {
		q.mu.Lock()

		if q.closing {
			q.mu.Unlock()
			return nil, ErrQueueClosed
		}

		wait := time.Hour

		if next, ok := q.pending.NextAttempt(); ok {
			if envelope := q.pending.PopDue(time.Now()); envelope != nil {
				delete(q.scheduled, envelope.ID)

				q.mu.Unlock()

				return envelope, nil
			}

			wait = time.Until(next)
		}

		q.mu.Unlock()

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		timer.Reset(wait)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-q.closeSignal:
			return nil, ErrQueueClosed
		case <-q.notify:
		case <-timer.C:
		}
	}
}

// Requeue puts an envelope back onto the schedule without disk I/O.
// Used when delivery is cancelled before a persistence attempt.
func (q *Queue) Requeue(envelope *Envelope) {
	if envelope == nil || q == nil || q.beginOperation() != nil {
		return
	}

	defer q.endOperation()

	q.mu.Lock()

	_, transitioning := q.transitioning[envelope.ID]
	if transitioning {
		for _, queued := range q.requeues[envelope.ID] {
			if queued.Incarnation == envelope.Incarnation && queued.Revision == envelope.Revision {
				q.mu.Unlock()

				return
			}
		}

		q.requeues[envelope.ID] = append(q.requeues[envelope.ID], cloneEnvelope(envelope))

		q.mu.Unlock()

		return
	}

	added := q.scheduleLocked(envelope)

	q.mu.Unlock()

	if added {
		q.signal()
	}
}

// RequeueAfter keeps a recoverable entry in memory but prevents a storage
// pressure failure from immediately cycling all delivery workers.
func (q *Queue) RequeueAfter(envelope *Envelope, delay time.Duration) {
	if envelope == nil || q == nil || q.beginOperation() != nil {
		return
	}

	defer q.endOperation()

	deferred := cloneEnvelope(envelope)

	deferred.NextAttempt = time.Now().Add(delay)

	q.mu.Lock()

	// Checked-out envelopes are absent from scheduled, which is the common
	// delivery-admission path. Only scan when replacing an existing schedule.
	if queued, scheduled := q.scheduled[envelope.ID]; scheduled {
		q.pending.Remove(queued)

		delete(q.scheduled, envelope.ID)
	}

	added := q.scheduleLocked(deferred)

	q.mu.Unlock()

	if added {
		q.signal()
	}
}

// Retry persists the updated envelope and reschedules it.
// On persistence failure the envelope is NOT removed from recoverability:
// it remains under ready/ and is returned to the schedule so a subsequent
// Open recovers it. The error is returned to the caller.
func (q *Queue) Retry(envelope *Envelope) error {
	if envelope == nil {
		return errNilEnvelope
	}

	err := q.beginOperation()
	if err != nil {
		return err
	}

	defer q.endOperation()

	err = q.rejectReadOnly()
	if err != nil {
		return err
	}

	err = ValidateID(envelope.ID)
	if err != nil {
		return err
	}

	err = q.beginTransition(envelope.ID)
	if err != nil {
		return err
	}

	owned := true

	defer func() {
		if owned {
			q.endTransition(envelope.ID)
		}
	}()

	err = q.startMutation()
	if err != nil {
		return err
	}

	mutationHeld := true

	defer func() {
		if mutationHeld {
			q.finishMutation()
		}
	}()

	publish := func() {
		if mutationHeld {
			q.finishMutation()

			mutationHeld = false
		}

		q.mu.Lock()
		delete(q.transitioning, envelope.ID)
		delete(q.requeues, envelope.ID)

		added := q.scheduleLocked(envelope)
		q.mu.Unlock()

		owned = false

		if added {
			q.signal()

			if q.afterPublish != nil {
				q.afterPublish()
			}
		}
	}

	err = validateEnvelope(envelope)
	if err != nil {
		// Reschedule the durable version rather than caller-mutated invalid data.
		durable, loadErr := q.loadAcceptedDir(filepath.Join(q.ready, envelope.ID), envelope.ID)
		if loadErr == nil {
			envelope = durable
		}

		publish()

		return err
	}

	meta, err := marshalEnvelope(envelope)
	if err != nil {
		publish()

		return err
	}

	release, err := q.holdPhysical(disk.AllocationSize(int64(len(meta))+disk.AllocationSize(0))+disk.AllocationSize(0), false)
	if err != nil {
		publish()

		return err
	}

	var commitHold bool

	defer func() {
		release(commitHold)
	}()

	commitHold, err = q.storeReady(envelope)
	if err != nil {
		// Keep the durable entry schedulable. Only a temp file that could not be
		// removed consumes additional cached usage.
		if !errors.Is(err, ErrIDConflict) {
			publish()
		}

		return err
	}

	publish()

	return nil
}

// Finish removes a fully handled message from the spool. Crash-safe: the
// directory is renamed into trash/ then removed. A crash after rename leaves
// a trash entry cleaned on Open.
func (q *Queue) Finish(envelope *Envelope) error {
	if envelope == nil {
		return errNilEnvelope
	}

	err := q.beginOperation()
	if err != nil {
		return err
	}

	defer q.endOperation()

	err = q.rejectReadOnly()
	if err != nil {
		return err
	}

	err = ValidateID(envelope.ID)
	if err != nil {
		return err
	}

	err = q.beginTransition(envelope.ID)
	if err != nil {
		return err
	}

	defer q.endTransition(envelope.ID)

	err = q.startMutation()
	if err != nil {
		return err
	}

	defer q.finishMutation()

	src := filepath.Join(q.ready, envelope.ID)

	err = q.matchReady(envelope)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	entryBytes, _ := disk.AllocatedBytes(src)

	dst := filepath.Join(q.trash, envelope.ID+"."+strconv.FormatInt(time.Now().UnixNano(), 10))

	err = disk.Mkdir(q.trash)
	if err != nil {
		return err
	}

	moved, err := moveState(src, dst)
	if err != nil {
		if moved || errors.Is(err, os.ErrNotExist) {
			// Already gone — treat as success for idempotence.
			q.noteRemoved(envelope.ID)

			if !moved {
				return nil
			}
		}

		return err
	}

	q.noteRemoved(envelope.ID)

	err = q.removeTrash(dst)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCleanup, err)
	}

	q.removePhysical(entryBytes)

	return nil
}
