package queue

import (
	"errors"
	"fmt"
	"os"
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

	opErr = q.startMutation()
	if opErr != nil {
		return 0, 0, opErr
	}

	defer q.finishMutation()

	q.validateDead()

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

		storedAt := info.ModTime()

		if namespace == q.corr {
			dot := strings.LastIndexByte(entry.Name(), '.')
			if dot >= 0 {
				stamp, parseErr := strconv.ParseInt(entry.Name()[dot+1:], 10, 64)
				if parseErr == nil {
					storedAt = time.Unix(0, stamp)
				}
			}
		}

		if now.Sub(storedAt) < retention || !validOpaqueName(entry.Name()) {
			continue
		}

		if namespace == q.dead {
			q.mu.Lock()
			_, busy := q.transitioning[entry.Name()]
			_, blocked := q.blocked[entry.Name()]
			q.mu.Unlock()

			if busy || blocked || ValidateID(entry.Name()) != nil {
				continue
			}
		}

		deleteErr := q.deleteStoredLocked(namespace, entry.Name(), prefix+sanitize(entry.Name()))
		if deleteErr != nil {
			errs = append(errs, fmt.Errorf("prune %s: %w", entry.Name(), deleteErr))

			continue
		}

		count++
	}

	return count, errors.Join(errs...)
}
