package queue

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Prune crash-safely deletes dead and corrupt entries older than their
// configured retention. Zero retention disables that namespace.
func (q *Queue) Prune(now time.Time) (dead, corrupt int, err error) {
	opErr := q.beginOperation()
	if opErr != nil {
		return 0, 0, opErr
	}

	defer q.endOperation()

	opErr = q.rejectReadOnly()
	if opErr != nil {
		return 0, 0, opErr
	}

	dead, deadErr := q.pruneNamespace(q.dead, q.limits.DeadRetention, now, "")
	corrupt, corruptErr := q.pruneNamespace(q.corr, q.limits.CorruptRetention, now, "corrupt-")

	return dead, corrupt, errors.Join(deadErr, corruptErr)
}

func (q *Queue) pruneNamespace(namespace string, retention time.Duration, now time.Time, prefix string) (int, error) {
	if retention <= 0 {
		return 0, nil
	}

	entries, err := os.ReadDir(namespace)
	if err != nil {
		return 0, err
	}

	initialDead := make(map[string]struct{})
	if namespace == q.dead {
		for _, entry := range entries {
			initialDead[entry.Name()] = struct{}{}
		}
	}

	var (
		count int
		errs  []error
	)

	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			errs = append(errs, infoErr)

			continue
		}

		storedAt := storedAt(namespace == q.corr, entry.Name(), info.ModTime())
		if now.Sub(storedAt) < retention || !validOpaqueName(entry.Name()) {
			continue
		}

		var deleted bool

		if namespace == q.dead {
			if ValidateID(entry.Name()) != nil {
				continue
			}

			deleted, infoErr = q.pruneDeadCandidate(entry.Name(), retention, now, initialDead)
		} else {
			deleted, infoErr = q.pruneCorruptCandidate(entry.Name(), retention, now, prefix)
		}

		if infoErr != nil {
			if !errors.Is(infoErr, ErrIDConflict) && !errors.Is(infoErr, ErrQueueBusy) {
				errs = append(errs, fmt.Errorf("prune %s: %w", entry.Name(), infoErr))
			}

			continue
		}

		if deleted {
			count++
		}
	}

	return count, errors.Join(errs...)
}

func (q *Queue) pruneDeadCandidate(id string, retention time.Duration, now time.Time, initialDead map[string]struct{}) (bool, error) {
	err := q.beginTransition(id)
	if err != nil {
		return false, err
	}

	linkedDSNID := ""

	defer func() {
		q.endTransitions(id, linkedDSNID)
	}()

	err = q.startMutation()
	if err != nil {
		return false, err
	}

	defer q.finishMutation()

	path := filepath.Join(q.dead, id)

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}

		return false, err
	}

	if now.Sub(info.ModTime()) < retention {
		return false, nil
	}

	if !info.IsDir() {
		cause := corruptionf("stray file in dead")

		err = q.quarantineFile(path, id+"-dead-stray")
		if err != nil {
			q.recordQuarantineFailure(id, path, cause, err)

			return false, err
		}

		q.noteRemoved(id)

		q.mu.Lock()
		q.Corrupt = append(q.Corrupt, fmt.Errorf("dead %s: %w", id, cause))
		q.mu.Unlock()

		return false, nil
	}

	envelope, err := q.loadAcceptedDir(path, id)
	if err != nil {
		if !IsCorruption(err) {
			return false, err
		}

		cause := err

		err = q.quarantineDir(path, id+"-invalid-dead")
		if err != nil {
			q.recordQuarantineFailure(id, path, cause, err)

			return false, err
		}

		q.noteRemoved(id)

		q.mu.Lock()
		q.Corrupt = append(q.Corrupt, fmt.Errorf("dead %s: %w", id, cause))
		q.mu.Unlock()

		return false, nil
	}

	if envelope.DSNSourceID == "" && envelope.DSNID != "" {
		if _, existed := initialDead[envelope.DSNID]; existed {
			return false, nil
		}
	}

	linkedDSNID, err = q.claimLinkedDeadDSN(envelope)
	if err != nil {
		return false, err
	}

	err = q.deleteStoredLocked(q.dead, id, sanitize(id))
	if err != nil {
		return false, err
	}

	return true, nil
}

func (q *Queue) pruneCorruptCandidate(name string, retention time.Duration, now time.Time, prefix string) (bool, error) {
	err := q.startMutation()
	if err != nil {
		return false, err
	}

	defer q.finishMutation()

	path := filepath.Join(q.corr, name)

	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}

		return false, err
	}

	if now.Sub(storedAt(true, name, info.ModTime())) < retention {
		return false, nil
	}

	err = q.deleteStoredLocked(q.corr, name, prefix+sanitize(name))
	if err != nil {
		return false, err
	}

	return true, nil
}

func storedAt(corrupt bool, name string, fallback time.Time) time.Time {
	if !corrupt {
		return fallback
	}

	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return fallback
	}

	stamp, err := strconv.ParseInt(name[dot+1:], 10, 64)
	if err != nil {
		return fallback
	}

	return time.Unix(0, stamp)
}
