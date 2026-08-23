package queue

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coalaura/outboxd/internal/disk"
)

// AddDSN durably links a generated DSN to its source before making the DSN
// schedulable. Recovery completes a linked stage after a crash.
func (q *Queue) AddDSN(source, dsn *Envelope, data []byte) error {
	err := q.beginOperation()
	if err != nil {
		return err
	}

	defer q.endOperation()

	err = q.rejectReadOnly()
	if err != nil {
		return err
	}

	if source == nil || dsn == nil {
		return errors.New("missing DSN envelope")
	}

	err = ValidateID(source.ID)
	if err != nil {
		return err
	}

	if dsn.DSNSourceID != source.ID || dsn.DSNSourceIncarnation != source.Incarnation || dsn.DSNGeneration != source.DSNGeneration || dsn.ID != DSNID(source.ID, source.Incarnation, source.DSNGeneration) {
		return fmt.Errorf("%w: DSN identity mismatch", ErrIDConflict)
	}

	if source.DSNSourceID != "" {
		return errors.New("cannot generate a DSN for a DSN")
	}

	if source.Pending() != 0 {
		return errors.New("cannot generate a DSN while recipients are pending")
	}

	if source.Failed() == 0 {
		return errors.New("cannot generate a DSN without failed recipients")
	}

	if dsn.Incarnation == "" {
		incarnation, err := newIncarnation()
		if err != nil {
			return err
		}

		dsn.Incarnation = incarnation
	}

	dsn.Revision = 1
	dsn.Size = int64(len(data))
	dsn.BodyDigest = bodyDigest(data)

	err = q.beginTransitions(source.ID, dsn.ID)
	if err != nil {
		return err
	}

	owned := true

	defer func() {
		if owned {
			q.endTransitions(source.ID, dsn.ID)
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

	q.mu.Lock()
	_, sourceBlocked := q.blocked[source.ID]
	_, dsnBlocked := q.blocked[dsn.ID]
	q.mu.Unlock()

	if sourceBlocked || dsnBlocked {
		return fmt.Errorf("%w: DSN source or destination is blocked by unresolved corruption", ErrIDConflict)
	}

	sourceDir := filepath.Join(q.ready, source.ID)

	durableSource, err := q.loadAcceptedDir(sourceDir, source.ID)
	if err != nil {
		return err
	}

	if durableSource.DSNGeneration != source.DSNGeneration {
		return fmt.Errorf("%w: source DSN generation changed", ErrIDConflict)
	}

	if durableSource.Incarnation != source.Incarnation {
		return fmt.Errorf("%w: source incarnation changed", ErrIDConflict)
	}

	if durableSource.Size != source.Size || durableSource.BodyDigest != source.BodyDigest {
		return fmt.Errorf("%w: source body identity changed", ErrIDConflict)
	}

	if !sameMessageContent(durableSource, source) {
		return fmt.Errorf("%w: source message identity changed", ErrIDConflict)
	}

	if durableSource.DSNID != "" {
		if durableSource.DSNID != dsn.ID {
			return fmt.Errorf("%w: source links %s", ErrIDConflict, durableSource.DSNID)
		}

		staged, published, publishErr := q.publishStagedDSN(durableSource, dsn)
		if published {
			q.finishMutation()

			mutationHeld = false

			q.mu.Lock()
			q.noteAddedLocked(staged)

			delete(q.transitioning, source.ID)
			delete(q.transitioning, dsn.ID)
			delete(q.requeues, source.ID)
			delete(q.requeues, dsn.ID)

			q.scheduleLocked(staged)
			q.mu.Unlock()

			owned = false

			q.signal()

			if q.afterPublish != nil {
				q.afterPublish()
			}
		}

		if publishErr != nil {
			return publishErr
		}

		source.DSNID = dsn.ID
		source.Revision = durableSource.Revision

		return nil
	}

	if durableSource.Revision != source.Revision {
		return fmt.Errorf("%w: source metadata changed", ErrIDConflict)
	}

	expectedSourceRevision, err := incrementRevision(durableSource.Revision)
	if err != nil {
		return err
	}

	dsn.DSNSourceRevision = expectedSourceRevision

	err = validateEnvelope(dsn)
	if err != nil {
		return err
	}

	err = verifyBodyData(dsn, data)
	if err != nil {
		return err
	}

	meta, err := marshalEnvelope(dsn)
	if err != nil {
		return err
	}

	linked := cloneEnvelope(source)

	linked.DSNID = dsn.ID

	err = validateEnvelope(linked)
	if err != nil {
		return err
	}

	linkedMeta, err := marshalEnvelope(linked)
	if err != nil {
		return err
	}

	persistentPhysical := estimatePersistentEntryAllocation(dsn.Size, len(meta))

	stagingPhysical := disk.AllocationSize(0)
	sourceTempPhysical := disk.AllocationSize(int64(len(linkedMeta)))
	replacementPhysical := disk.AllocationSize(int64(len(linkedMeta))+disk.AllocationSize(0)) + disk.AllocationSize(0)

	physical, ok := checkedAddInt64(persistentPhysical, stagingPhysical)
	if ok {
		physical, ok = checkedAddInt64(physical, replacementPhysical)
	}

	if !ok {
		return ErrSpoolFull
	}

	for _, dir := range []string{q.ready, q.dead} {
		if _, err := os.Stat(filepath.Join(dir, dsn.ID)); err == nil {
			return fmt.Errorf("%w: %s already exists", ErrIDConflict, dsn.ID)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	stageDir := filepath.Join(q.dsn, dsn.ID)
	_, err = os.Stat(stageDir)
	if err == nil {
		// The durable source is unlinked, so an existing stage never crossed the
		// protocol commit point and can be replaced by this retry.
		stageBytes, _ := disk.AllocatedBytes(stageDir)

		err = disk.RemoveAll(stageDir)
		if err != nil {
			return err
		}

		err = disk.Sync(q.dsn)
		if err != nil {
			return err
		}

		q.removePhysical(stageBytes)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	q.mu.Lock()

	err = q.reserveLocked(dsn.Size, physical, true, true, "")
	if err != nil {
		q.mu.Unlock()

		return err
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
			q.releaseReserve(dsn.Size, physicalHeld, "")
		}
	}()

	err = disk.MkdirDurable(stageDir)
	if err != nil {
		return err
	}

	cleanup := true

	defer func() {
		if cleanup {
			removeErr := disk.RemoveAll(stageDir)
			syncErr := disk.Sync(q.dsn)

			if removeErr != nil || syncErr != nil {
				commitPhysical(persistentPhysical + stagingPhysical)
			}
		}
	}()

	err = disk.Write(filepath.Join(stageDir, addStateName), []byte(addPending), 0600)
	if err != nil {
		return err
	}

	err = disk.Write(filepath.Join(stageDir, bodyName), data, 0600)
	if err != nil {
		return err
	}

	err = disk.Write(filepath.Join(stageDir, metaName), meta, 0600)
	if err != nil {
		return err
	}

	err = disk.Sync(stageDir)
	if err != nil {
		return err
	}

	err = q.acceptAdd(stageDir)
	if err != nil {
		return err
	}

	// The accepted stage remains recoverable across every later error. Move its
	// persistent allocation into committed usage before linking the source.
	commitPhysical(persistentPhysical)

	retainedSourceTemp, storeErr := q.storeReadyDSNLink(linked)
	if retainedSourceTemp {
		commitPhysical(sourceTempPhysical)
	}

	if storeErr != nil {
		// Visibility after a failed source-directory sync is not a durability
		// barrier. Preserve the accepted stage for a retry or startup recovery.
		cleanup = false

		commitPhysical(stagingPhysical)

		q.mu.Lock()
		q.requeues[source.ID] = append(q.requeues[source.ID], cloneEnvelope(durableSource))
		q.mu.Unlock()

		return storeErr
	}

	cleanup = false

	staged, moved, err := q.publishStagedDSN(linked, dsn)
	if err != nil && !moved {
		commitPhysical(stagingPhysical)

		return err
	}

	q.finishMutation()

	mutationHeld = false

	q.mu.Lock()
	q.releaseReserveLocked(dsn.Size, physicalHeld, "")

	q.noteAddedLocked(staged)

	delete(q.transitioning, source.ID)
	delete(q.transitioning, dsn.ID)
	delete(q.requeues, source.ID)
	delete(q.requeues, dsn.ID)

	q.scheduleLocked(dsn)
	q.mu.Unlock()

	held = false
	owned = false

	source.DSNID = dsn.ID
	source.Revision = linked.Revision

	q.signal()

	if q.afterPublish != nil {
		q.afterPublish()
	}

	return errors.Join(storeErr, err)
}

func (q *Queue) publishStagedDSN(expectedSource, dsn *Envelope) (*Envelope, bool, error) {
	sourceDir := filepath.Join(q.ready, dsn.DSNSourceID)

	// This barrier is deliberately separate from metadata replacement. It is
	// required even on same-process retries after an ambiguous sync failure.
	err := disk.Sync(sourceDir)
	if err != nil {
		return nil, false, err
	}

	durableSource, err := q.loadAcceptedDir(sourceDir, dsn.DSNSourceID)
	if err != nil {
		return nil, false, err
	}

	if durableSource.Incarnation != dsn.DSNSourceIncarnation || durableSource.DSNGeneration != dsn.DSNGeneration || durableSource.DSNID != dsn.ID {
		return nil, false, fmt.Errorf("%w: source DSN link changed", ErrIDConflict)
	}

	if expectedSource != nil && (durableSource.Incarnation != expectedSource.Incarnation || durableSource.Revision != expectedSource.Revision) {
		return nil, false, fmt.Errorf("%w: source metadata changed before DSN publication", ErrIDConflict)
	}

	stageDir := filepath.Join(q.dsn, dsn.ID)

	_, err = os.Stat(stageDir)
	if errors.Is(err, os.ErrNotExist) {
		readyDir := filepath.Join(q.ready, dsn.ID)

		existing, readyErr := q.loadAcceptedDir(readyDir, dsn.ID)
		if readyErr == nil {
			if !sameDSNIdentity(existing, dsn) || existing.DSNSourceRevision != durableSource.Revision {
				return nil, false, fmt.Errorf("%w: published DSN identity changed", ErrIDConflict)
			}

			return existing, false, nil
		}

		if !errors.Is(readyErr, os.ErrNotExist) {
			return nil, false, readyErr
		}

		// A missing stage and ready entry means an exactly linked DSN already
		// completed. The accepted source identity above is still authoritative.
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}

	staged, err := q.loadAcceptedDir(stageDir, dsn.ID)
	if err != nil {
		return nil, false, err
	}

	if !sameDSNIdentity(staged, dsn) || staged.DSNSourceRevision != durableSource.Revision {
		return nil, false, fmt.Errorf("%w: staged DSN identity mismatch", ErrIDConflict)
	}

	moved, err := moveState(stageDir, filepath.Join(q.ready, dsn.ID))
	if err != nil && !moved {
		return nil, false, err
	}

	return staged, true, err
}

func sameDSNIdentity(a, b *Envelope) bool {
	return a.ID == b.ID && a.Incarnation == b.Incarnation && a.DSNSourceID == b.DSNSourceID && a.DSNSourceIncarnation == b.DSNSourceIncarnation && a.DSNGeneration == b.DSNGeneration
}
