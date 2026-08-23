package queue

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/coalaura/outboxd/internal/disk"
)

// Add durably stores a message and schedules it for immediate delivery.
// The accepted marker is the commit point: before it is synced, neither tmp/
// nor a pending ready/ entry is recoverable as an accepted message.
func (q *Queue) Add(envelope *Envelope, data []byte) error {
	return q.AddContext(context.Background(), envelope, data)
}

// AddContext is Add with precommit cancellation. Once the accepted marker has
// synced, acceptance wins over cancellation and the message is published.
func (q *Queue) AddContext(ctx context.Context, envelope *Envelope, data []byte) error {
	if ctx == nil {
		return errors.New("nil Add context")
	}

	if err := ctx.Err(); err != nil {
		return err
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

	if envelope == nil {
		return errors.New("missing envelope")
	}

	err = ValidateID(envelope.ID)
	if err != nil {
		return err
	}

	if envelope.DSNSourceID != "" || envelope.DSNID != "" || envelope.DSNGeneration != 0 {
		return errors.New("DSN state is managed by AddDSN and ReviveDead")
	}

	incarnation, err := newIncarnation()
	if err != nil {
		return err
	}

	envelope.Incarnation = incarnation
	envelope.Revision = 1

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

	if err = ctx.Err(); err != nil {
		return err
	}

	q.mu.Lock()
	_, blocked := q.blocked[envelope.ID]
	_, exists := q.accounted[envelope.ID]
	q.mu.Unlock()

	if blocked {
		return fmt.Errorf("%w: queue id %s is blocked by an unresolved corrupt entry", ErrIDConflict, envelope.ID)
	}

	if exists {
		return fmt.Errorf("%w: queue id %s is already ready", ErrIDConflict, envelope.ID)
	}

	readyDir := filepath.Join(q.ready, envelope.ID)

	_, err = os.Stat(readyDir)
	if err == nil {
		state, stateErr := readBoundedRegular(filepath.Join(readyDir, addStateName), maxAddStateBytes)
		if stateErr != nil {
			return stateErr
		}

		if string(state) == addAccepted {
			return fmt.Errorf("%w: queue id %s already exists", ErrIDConflict, envelope.ID)
		}

		err = q.quarantineDir(readyDir, envelope.ID+"-uncommitted")
		if err != nil {
			return fmt.Errorf("reconcile prior uncommitted add: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	for _, dir := range []string{q.dead, q.dsn} {
		if _, err := os.Stat(filepath.Join(dir, envelope.ID)); err == nil {
			return fmt.Errorf("%w: queue id %s already exists", ErrIDConflict, envelope.ID)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	envelope.Size = int64(len(data))
	envelope.BodyDigest = bodyDigest(data)

	err = validateEnvelope(envelope)
	if err != nil {
		return err
	}

	err = verifyBodyData(envelope, data)
	if err != nil {
		return err
	}

	meta, err := marshalEnvelope(envelope)
	if err != nil {
		return err
	}

	if err = ctx.Err(); err != nil {
		return err
	}

	physical := estimateEntryAllocation(envelope.Size, len(meta))

	// Capacity check accounts for concurrent in-progress connections via reserved.
	q.mu.Lock()

	err = q.reserveLocked(envelope.Size, physical, false, false, envelope.Username)
	if err != nil {
		q.mu.Unlock()

		return err
	}

	q.mu.Unlock()

	held := true

	physicalHeld := physical

	commitPhysical := func() {
		if physicalHeld == 0 {
			return
		}

		q.mu.Lock()
		q.commitPhysicalLocked(physicalHeld)
		q.mu.Unlock()

		physicalHeld = 0
	}

	defer func() {
		if held {
			q.releaseReserve(envelope.Size, physicalHeld, envelope.Username)
		}
	}()

	if err = ctx.Err(); err != nil {
		return err
	}

	tmpDir := filepath.Join(q.tmp, envelope.ID)

	err = disk.RemoveAll(tmpDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	err = disk.Mkdir(tmpDir)
	if err != nil {
		return err
	}

	// Cleanup tmp on any failure after creation.
	var success bool

	defer func() {
		if !success {
			removeErr := disk.RemoveAll(tmpDir)
			syncErr := disk.Sync(q.tmp)

			_, tmpErr := os.Lstat(tmpDir)
			_, readyErr := os.Lstat(readyDir)

			if removeErr != nil || syncErr != nil || tmpErr == nil || readyErr == nil {
				commitPhysical()
			}
		}
	}()

	statePath := filepath.Join(tmpDir, addStateName)
	if err = ctx.Err(); err != nil {
		return err
	}

	err = disk.Write(statePath, []byte(addPending), 0600)
	if err != nil {
		return err
	}

	bodyPath := filepath.Join(tmpDir, bodyName)
	if err = ctx.Err(); err != nil {
		return err
	}

	err = disk.Write(bodyPath, data, 0600)
	if err != nil {
		return err
	}

	metaPath := filepath.Join(tmpDir, metaName)
	if err = ctx.Err(); err != nil {
		return err
	}

	err = disk.Write(metaPath, meta, 0600)
	if err != nil {
		return err
	}

	if err = ctx.Err(); err != nil {
		return err
	}

	err = disk.Sync(tmpDir)
	if err != nil {
		return err
	}

	if err = ctx.Err(); err != nil {
		return err
	}

	err = disk.Rename(tmpDir, readyDir)
	if err != nil {
		return err
	}

	abortReady := func(cause error) error {
		persistent := estimatePersistentEntryAllocation(envelope.Size, len(meta))
		if measured, measureErr := disk.AllocatedBytes(readyDir); measureErr == nil {
			persistent = measured
		}

		abortErr := q.quarantineDir(readyDir, envelope.ID+"-uncommitted")

		// Quarantine intentionally retains the failed entry. If quarantine itself
		// failed, the entry may remain in either namespace and must still be charged.
		commitPhysicalBytes := min(persistent, physicalHeld)

		q.mu.Lock()
		q.commitPhysicalLocked(commitPhysicalBytes)
		q.mu.Unlock()

		physicalHeld -= commitPhysicalBytes

		success = true

		if abortErr == nil {
			return definiteAcceptanceCause(cause)
		}

		// A relocation can report a post-rename sync error. A fresh successful
		// ready-directory sync proving the source absent resolves that ambiguity.
		syncErr := disk.Sync(q.ready)
		_, statErr := os.Stat(readyDir)
		if syncErr == nil && errors.Is(statErr, os.ErrNotExist) {
			return errors.Join(definiteAcceptanceCause(cause), fmt.Errorf("quarantine reported an error after removing ready entry: %w", abortErr))
		}

		cleanupErr := errors.Join(abortErr, syncErr)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, statErr)
		}

		if IsAcceptanceUnknown(cause) {
			q.mu.Lock()
			q.blocked[envelope.ID] = struct{}{}
			q.mu.Unlock()

			return acceptanceUnknown(errors.Join(definiteAcceptanceCause(cause), fmt.Errorf("quarantine failed add: %w", cleanupErr)))
		}

		return errors.Join(cause, fmt.Errorf("quarantine failed add: %w", cleanupErr))
	}

	if err = ctx.Err(); err != nil {
		return abortReady(err)
	}

	err = q.acceptAdd(readyDir)
	if err != nil {
		return abortReady(err)
	}

	success = true
	held = false

	q.finishMutation()

	mutationHeld = false

	q.mu.Lock()
	persistentPhysical := estimatePersistentEntryAllocation(envelope.Size, len(meta))

	q.commitPhysicalLocked(persistentPhysical)

	physicalHeld -= persistentPhysical

	q.releaseReserveLocked(envelope.Size, physicalHeld, envelope.Username)

	physicalHeld = 0

	q.noteAddedLocked(envelope)

	delete(q.transitioning, envelope.ID)
	delete(q.requeues, envelope.ID)

	q.scheduleLocked(envelope)
	q.mu.Unlock()

	owned = false

	q.signal()

	if q.afterPublish != nil {
		q.afterPublish()
	}

	return nil
}

// acceptAdd performs the sole Add acceptance transition. The marker already
// has a durable directory entry, so only its fixed-size contents need syncing.
// No fallible operation is reported after the successful Sync commit point.
func (q *Queue) acceptAdd(dir string) error {
	if len(addPending) != len(addAccepted) {
		panic("queue Add states must have equal length")
	}

	file, err := os.OpenFile(filepath.Join(dir, addStateName), os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	defer file.Close()

	err = writeAddState(file, addAccepted)
	if err != nil {
		rolledBack, result := q.rollbackAdd(file, err)
		if !rolledBack {
			return acceptanceUnknown(result)
		}

		return result
	}

	err = disk.SyncFile(file)
	if err != nil {
		rolledBack, result := q.rollbackAdd(file, err)
		if !rolledBack {
			return acceptanceUnknown(result)
		}

		return result
	}

	return nil
}

func (q *Queue) rollbackAdd(file *os.File, cause error) (bool, error) {
	// A failed commit must not leave accepted bytes recoverable after Add
	// reports failure. A successful rollback sync restores that invariant.
	if q.beforeAddRollback != nil {
		err := q.beforeAddRollback()
		if err != nil {
			return false, errors.Join(cause, fmt.Errorf("rollback add state: %w", err))
		}
	}

	err := writeAddState(file, addPending)
	if err != nil {
		return false, errors.Join(cause, fmt.Errorf("rollback add state: %w", err))
	}

	err = disk.SyncFile(file)
	if err != nil {
		return false, errors.Join(cause, fmt.Errorf("sync rolled-back add state: %w", err))
	}

	return true, cause
}

func writeAddState(file *os.File, state string) error {
	n, err := file.WriteAt([]byte(state), 0)
	if err != nil {
		return err
	}

	if n != len(state) {
		return io.ErrShortWrite
	}

	return nil
}
