package queue

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
)

// Bury moves an undeliverable message into the dead-letter directory atomically
// (single directory rename). Metadata is written first inside ready/.
func (q *Queue) Bury(envelope *Envelope) error {
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

	reschedule := func() {
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

		reschedule()

		return err
	}

	meta, err := marshalEnvelope(envelope)
	if err != nil {
		reschedule()

		return err
	}

	release, err := q.holdPhysical(disk.AllocationSize(int64(len(meta))+disk.AllocationSize(0))+disk.AllocationSize(0), true)
	if err != nil {
		reschedule()

		return err
	}

	var commitHold bool

	defer func() {
		release(commitHold)
	}()

	src := filepath.Join(q.ready, envelope.ID)
	dst := filepath.Join(q.dead, envelope.ID)

	err = q.matchReady(envelope)
	if err != nil {
		_, srcErr := os.Stat(src)
		if errors.Is(srcErr, os.ErrNotExist) {
			dead, deadErr := q.loadAcceptedDir(dst, envelope.ID)
			if deadErr == nil {
				if dead.Incarnation != envelope.Incarnation || dead.Revision != envelope.Revision {
					return fmt.Errorf("%w: dead-letter identity changed", ErrIDConflict)
				}

				q.noteRemoved(envelope.ID)

				return nil
			}

			if !errors.Is(deadErr, os.ErrNotExist) {
				return deadErr
			}
		}

		if !errors.Is(err, ErrIDConflict) {
			reschedule()
		}

		return err
	}

	_, err = os.Stat(dst)
	if err == nil {
		reschedule()

		return fmt.Errorf("%w: dead-letter id %s already exists", ErrIDConflict, envelope.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		reschedule()

		return err
	}

	// Persist final status inside ready/ before the rename.
	commitHold, err = q.storeReady(envelope)
	if err != nil {
		// Reschedule for recoverability; signal fatal to caller.
		if !errors.Is(err, ErrIDConflict) {
			reschedule()
		}

		return err
	}
	moved, err := moveState(src, dst)
	if err != nil {
		if moved {
			q.noteRemoved(envelope.ID)
		} else {
			reschedule()
		}

		return err
	}

	q.noteRemoved(envelope.ID)

	return nil
}

// ReviveDead moves a dead-letter item back to ready and schedules it.
func (q *Queue) ReviveDead(id string) (*Envelope, error) {
	err := q.beginOperation()
	if err != nil {
		return nil, err
	}

	defer q.endOperation()

	err = q.rejectReadOnly()
	if err != nil {
		return nil, err
	}

	err = ValidateID(id)
	if err != nil {
		return nil, err
	}

	err = q.beginTransition(id)
	if err != nil {
		return nil, err
	}

	owned := true

	defer func() {
		if owned {
			q.endTransition(id)
		}
	}()

	err = q.startMutation()
	if err != nil {
		return nil, err
	}

	mutationHeld := true

	defer func() {
		if mutationHeld {
			q.finishMutation()
		}
	}()

	q.mu.Lock()
	_, blocked := q.blocked[id]
	q.mu.Unlock()

	if blocked {
		return nil, fmt.Errorf("%w: queue id %s is blocked by an unresolved corrupt entry", ErrIDConflict, id)
	}

	src := filepath.Join(q.dead, id)

	err = acceptedDir(src)
	if err != nil {
		return nil, err
	}

	env, err := q.loadDir(src, id)
	if err != nil {
		return nil, err
	}

	oldEntryBytes, err := disk.AllocatedBytes(src)
	if err != nil {
		return nil, err
	}

	nextRevision, err := incrementRevision(env.Revision)
	if err != nil {
		return nil, err
	}

	if env.DSNSourceID == "" && env.DSNGeneration == math.MaxUint64 {
		return nil, errors.New("DSN generation overflow")
	}

	q.mu.Lock()

	_, exists := q.accounted[id]
	if exists {
		q.mu.Unlock()

		return nil, fmt.Errorf("queue id %s is already ready", id)
	}

	meta, err := marshalEnvelope(env)
	if err != nil {
		q.mu.Unlock()

		return nil, err
	}

	physical := 2*disk.AllocationSize(int64(len(meta))+disk.AllocationSize(0)) + disk.AllocationSize(0)

	exempt := env.DSNSourceID != ""
	owner := env.Username

	if exempt {
		owner = ""
	}

	err = q.reserveLocked(env.Size, physical, exempt, true, owner)
	if err != nil {
		q.mu.Unlock()
		return nil, err
	}

	q.mu.Unlock()

	held := true

	physicalHeld := physical

	commitPhysical := func(bytes int64) {
		if bytes <= 0 || physicalHeld == 0 {
			return
		}

		if bytes > physicalHeld {
			bytes = physicalHeld
		}

		q.mu.Lock()
		q.commitPhysicalLocked(bytes)
		q.mu.Unlock()

		physicalHeld -= bytes
	}

	defer func() {
		if held {
			q.releaseReserve(env.Size, physicalHeld, owner)
		}
	}()

	for i := range env.Recipients {
		if env.Recipients[i].Status == StatusFailed {
			env.Recipients[i].Status = StatusPending
			env.Recipients[i].Detail = ""
			env.Recipients[i].Code = 0
			env.Recipients[i].EnhancedCode = ""
		}
	}

	env.Attempts = 0
	env.LastError = ""
	env.NextAttempt = time.Now()

	if env.DSNSourceID == "" {
		env.DSNGeneration++
		env.DSNID = ""
	}

	env.Revision = nextRevision

	err = validateEnvelope(env)
	if err != nil {
		return nil, err
	}

	stagedMeta := filepath.Join(src, reviveMetaName)

	_, retainedStageTemp, err := q.writeMetaReconciled(stagedMeta, env)
	if err != nil {
		cleanupErr := removeAndSync(stagedMeta)
		if retainedStageTemp {
			commitPhysical(disk.AllocationSize(int64(len(meta))))
		}

		if cleanupErr != nil {
			commitPhysical(disk.AllocationSize(int64(len(meta))) + disk.AllocationSize(0))
		}

		return nil, errors.Join(err, cleanupErr)
	}

	dst := filepath.Join(q.ready, id)

	moved, moveErr := moveState(src, dst)
	if moveErr != nil && !moved {
		cleanupErr := removeAndSync(stagedMeta)
		if cleanupErr != nil {
			commitPhysical(disk.AllocationSize(int64(len(meta))) + disk.AllocationSize(0))
		}

		return nil, errors.Join(moveErr, cleanupErr)
	}

	activated, activateErr := moveState(filepath.Join(dst, reviveMetaName), filepath.Join(dst, metaName))
	if activateErr != nil && !activated {
		rolledBack, rollbackErr := moveState(dst, src)
		if rolledBack {
			cleanupErr := removeAndSync(filepath.Join(src, reviveMetaName))
			if cleanupErr != nil {
				commitPhysical(disk.AllocationSize(int64(len(meta))) + disk.AllocationSize(0))
			}

			return nil, errors.Join(moveErr, activateErr, rollbackErr, cleanupErr)
		}

		committed, retainedReplacementTemp, reconcileErr := q.writeMetaReconciled(filepath.Join(dst, metaName), env)
		if retainedReplacementTemp {
			commitPhysical(disk.AllocationSize(int64(len(meta))))
		}

		if !committed {
			return nil, errors.Join(moveErr, activateErr, fmt.Errorf("rollback revive: %w", rollbackErr), reconcileErr)
		}

		cleanupErr := removeAndSync(filepath.Join(dst, reviveMetaName))
		if cleanupErr != nil {
			commitPhysical(disk.AllocationSize(int64(len(meta))) + disk.AllocationSize(0))
		}

		activateErr = errors.Join(activateErr, fmt.Errorf("rollback revive: %w", rollbackErr), reconcileErr, cleanupErr)
	}

	if activateErr != nil {
		moveErr = errors.Join(moveErr, activateErr)
	}

	newEntryBytes, measureErr := disk.AllocatedBytes(dst)
	if measureErr != nil {
		commitPhysical(disk.AllocationSize(int64(len(meta))) + disk.AllocationSize(0))

		moveErr = errors.Join(moveErr, fmt.Errorf("measure revived entry: %w", measureErr))
	} else {
		q.adjustPhysicalDelta(oldEntryBytes, newEntryBytes)
	}

	q.finishMutation()

	mutationHeld = false

	q.mu.Lock()
	q.releaseReserveLocked(env.Size, physicalHeld, owner)

	q.noteAddedLocked(env)

	delete(q.transitioning, id)
	delete(q.requeues, id)

	q.scheduleLocked(env)
	q.mu.Unlock()

	held = false
	owned = false

	q.signal()

	if q.afterPublish != nil {
		q.afterPublish()
	}

	return env, moveErr
}
