package queue

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
)

// QuarantineCheckedOut removes only the exact checked-out ready incarnation
// whose deterministic integrity failure is supplied in cause. A failed move
// blocks that ID in memory so unrelated entries remain deliverable.
func (q *Queue) QuarantineCheckedOut(envelope *Envelope, cause error) error {
	if envelope == nil || !IsCorruption(cause) {
		return errors.New("checked-out quarantine requires a corruption error")
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

	q.mu.Lock()
	entry, accounted := q.accounted[envelope.ID]

	_, scheduled := q.scheduled[envelope.ID]
	q.mu.Unlock()

	if !accounted || scheduled || entry.incarnation != envelope.Incarnation || entry.revision != envelope.Revision {
		return fmt.Errorf("%w: checked-out queue identity changed", ErrIDConflict)
	}

	current, err := loadAcceptedMetadata(filepath.Join(q.ready, envelope.ID), envelope.ID)
	if err != nil {
		q.blockCheckedOut(envelope.ID, cause, fmt.Errorf("verify checked-out identity: %w", err))

		return err
	}
	if current.Incarnation != envelope.Incarnation || current.Revision != envelope.Revision || current.Size != envelope.Size || current.BodyDigest != envelope.BodyDigest {
		err := fmt.Errorf("%w: checked-out queue identity changed", ErrIDConflict)

		q.blockCheckedOut(envelope.ID, cause, err)

		return err
	}

	src := filepath.Join(q.ready, envelope.ID)
	dst := filepath.Join(q.corr, envelope.ID+"-runtime."+strconv.FormatInt(time.Now().UnixNano(), 10))

	err = ensureDurableDir(q.corr)
	if err != nil {
		q.blockCheckedOut(envelope.ID, cause, err)

		return err
	}

	moved, moveErr := moveState(src, dst)
	if !moved {
		q.blockCheckedOut(envelope.ID, cause, moveErr)

		return moveErr
	}

	q.noteRemoved(envelope.ID)

	q.mu.Lock()
	if moveErr != nil {
		q.blocked[envelope.ID] = struct{}{}

		q.Corrupt = append(q.Corrupt, fmt.Errorf("QUARANTINE DURABILITY FAILED; BLOCKED %s: %v (relocation: %w)", envelope.ID, cause, moveErr))
	} else {
		q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: %w", envelope.ID, cause))
	}
	q.mu.Unlock()

	return moveErr
}

func (q *Queue) blockCheckedOut(id string, cause, relocation error) {
	q.mu.Lock()
	q.blocked[id] = struct{}{}

	if queued := q.scheduled[id]; queued != nil {
		q.pending.Remove(queued)

		delete(q.scheduled, id)
	}

	q.Corrupt = append(q.Corrupt, fmt.Errorf("QUARANTINE FAILED; BLOCKED %s: %v (relocation: %w)", id, cause, relocation))
	q.mu.Unlock()
}

// CorruptIDs lists quarantined entry names. Names are opaque and can be passed
// back to DeleteCorrupt.
func (q *Queue) CorruptIDs() ([]string, error) {
	err := q.beginOperation()
	if err != nil {
		return nil, err
	}

	defer q.endOperation()

	entries, err := os.ReadDir(q.corr)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(entries))

	for _, entry := range entries {
		if validOpaqueName(entry.Name()) {
			ids = append(ids, entry.Name())
		}
	}

	return ids, nil
}

// DeleteCorrupt crash-safely moves one opaque quarantine entry through trash.
func (q *Queue) DeleteCorrupt(name string) error {
	if !validOpaqueName(name) {
		return ErrInvalidID
	}

	return q.deleteStored(q.corr, name, "corrupt-"+sanitize(name))
}

func (q *Queue) recordQuarantineFailure(id, path string, cause, quarantineErr error) {
	q.blocked[id] = struct{}{}

	q.Corrupt = append(q.Corrupt, fmt.Errorf("QUARANTINE FAILED; BLOCKED %s at %s: %v (relocation: %w)", id, path, cause, quarantineErr))
}

func (q *Queue) recordBlocked(id, path string, cause error) {
	q.blocked[id] = struct{}{}

	q.Corrupt = append(q.Corrupt, fmt.Errorf("BLOCKED %s at %s: %w", id, path, cause))
}

func (q *Queue) recordTransientBlocked(id, path string, cause error) {
	q.blocked[id] = struct{}{}

	q.Warnings = append(q.Warnings, fmt.Errorf("TRANSIENTLY BLOCKED %s at %s: %w", id, path, cause))
}

func (q *Queue) quarantineDir(src, name string) error {
	err := ensureDurableDir(q.corr)
	if err != nil {
		return err
	}

	dst := filepath.Join(q.corr, name+"."+strconv.FormatInt(time.Now().UnixNano(), 10))

	err = disk.Rename(src, dst)
	if err != nil {
		// fallback copy-ish remove
		return fmt.Errorf("quarantine %s: %w", src, err)
	}

	return nil
}

func (q *Queue) quarantineFile(src, name string) error {
	err := ensureDurableDir(q.corr)
	if err != nil {
		return err
	}

	dstDir := filepath.Join(q.corr, name+"."+strconv.FormatInt(time.Now().UnixNano(), 10))

	err = disk.MkdirDurable(dstDir)
	if err != nil {
		return err
	}

	dst := filepath.Join(dstDir, filepath.Base(src))

	err = disk.Rename(src, dst)
	if err != nil {
		removeErr := os.Remove(dstDir)
		syncErr := disk.Sync(q.corr)

		return errors.Join(fmt.Errorf("quarantine file %s: %w", src, err), removeErr, syncErr)
	}

	return nil
}
