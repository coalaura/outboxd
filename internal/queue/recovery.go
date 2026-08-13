package queue

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coalaura/outboxd/internal/disk"
)

var errDSNSourceScanIncomplete = errors.New("DSN source scan incomplete")

func (q *Queue) recoverTmp() error {
	entries, err := os.ReadDir(q.tmp)
	if err != nil {
		return err
	}

	for _, e := range entries {
		if !e.IsDir() {
			err = os.Remove(filepath.Join(q.tmp, e.Name()))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				q.Warnings = append(q.Warnings, fmt.Errorf("remove stray tmp file %s: %w", e.Name(), err))
			}

			continue
		}

		id := e.Name()
		dir := filepath.Join(q.tmp, id)

		// tmp entries have not crossed Add's acceptance point. Completeness is
		// not evidence of acceptance, so preserve them only for diagnosis.
		qerr := q.quarantineDir(dir, id+"-uncommitted")
		if qerr != nil {
			q.recordQuarantineFailure(id, dir, errors.New("interrupted uncommitted add"), qerr)

			continue
		}

		q.Corrupt = append(q.Corrupt, fmt.Errorf("tmp %s: interrupted uncommitted add", id))
	}

	return disk.Sync(q.tmp)
}

func (q *Queue) cleanTrash() error {
	entries, err := os.ReadDir(q.trash)
	if err != nil {
		return err
	}

	var errs []error

	for _, e := range entries {
		err = disk.RemoveAll(filepath.Join(q.trash, e.Name()))
		if err != nil {
			errs = append(errs, fmt.Errorf("remove trash %s: %w", e.Name(), err))
		}
	}

	err = disk.Sync(q.trash)
	if err != nil {
		errs = append(errs, fmt.Errorf("sync trash: %w", err))
	}

	return errors.Join(errs...)
}

func (q *Queue) validateDead() {
	entries, err := os.ReadDir(q.dead)
	if err != nil {
		q.Warnings = append(q.Warnings, fmt.Errorf("validate dead: %w", err))

		return
	}

	for _, entry := range entries {
		path := filepath.Join(q.dead, entry.Name())

		var cause error

		if !entry.IsDir() {
			cause = corruptionf("stray file in dead")

			err = q.quarantineFile(path, entry.Name()+"-dead-stray")
			if err != nil {
				q.recordQuarantineFailure(entry.Name(), path, cause, err)
			} else {
				q.Corrupt = append(q.Corrupt, fmt.Errorf("dead %s: %w", entry.Name(), cause))
			}

			continue
		}

		id := entry.Name()

		err = ValidateID(id)
		if err != nil {
			cause = corruptionf("invalid dead id %q", id)
		} else {
			_, cause = q.loadAcceptedDir(path, id)
		}

		if cause == nil {
			continue
		}

		if !IsCorruption(cause) {
			q.recordTransientBlocked(id, path, fmt.Errorf("validate dead: %w", cause))

			continue
		}

		err = q.quarantineDir(path, id+"-invalid-dead")
		if err != nil {
			q.recordQuarantineFailure(id, path, cause, err)

			continue
		}

		q.Corrupt = append(q.Corrupt, fmt.Errorf("dead %s: %w", id, cause))
	}
}

func (q *Queue) recoverDSN() error {
	entries, err := os.ReadDir(q.dsn)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		path := filepath.Join(q.dsn, entry.Name())
		if !entry.IsDir() {
			err = q.quarantineFile(path, entry.Name()+"-dsn-stray")
			if err != nil {
				q.recordQuarantineFailure(entry.Name(), path, corruptionf("stray file in dsn"), err)

				continue
			}

			q.Corrupt = append(q.Corrupt, fmt.Errorf("stray file in dsn: %s", entry.Name()))

			continue
		}

		id := entry.Name()

		dsn, err := q.loadAcceptedDir(path, id)
		if err != nil {
			if !IsCorruption(err) {
				q.recordTransientBlocked(id, path, fmt.Errorf("read staged DSN: %w", err))

				q.blockLinkedSource(id, err)

				continue
			}

			qerr := q.quarantineDSNStage(path, id, "invalid", err)
			if errors.Is(qerr, errDSNSourceScanIncomplete) {
				q.recordTransientBlocked(id, path, qerr)

				continue
			}

			if qerr != nil {
				q.recordQuarantineFailure(id, path, err, qerr)
			}

			continue
		}

		sourceDir := filepath.Join(q.ready, dsn.DSNSourceID)

		err = disk.Sync(sourceDir)
		if err != nil {
			q.recordTransientBlocked(id, path, fmt.Errorf("establish source durability barrier: %w", err))
			q.recordTransientBlocked(dsn.DSNSourceID, sourceDir, fmt.Errorf("linked DSN %s source barrier failed", id))

			continue
		}

		source, err := q.loadAcceptedDir(sourceDir, dsn.DSNSourceID)
		if err != nil {
			if !IsCorruption(err) && !errors.Is(err, os.ErrNotExist) {
				q.recordTransientBlocked(id, path, fmt.Errorf("read linked DSN source: %w", err))
				q.recordTransientBlocked(dsn.DSNSourceID, sourceDir, fmt.Errorf("linked DSN %s source read failed", id))

				continue
			}

			cause := corruptionf("source link missing or invalid: %v", err)

			qerr := q.quarantineDSNStage(path, id, "orphan", cause)
			if qerr != nil {
				q.recordQuarantineFailure(id, path, cause, qerr)
			}

			continue
		}
		if source.Incarnation != dsn.DSNSourceIncarnation || source.Revision != dsn.DSNSourceRevision || source.DSNID != dsn.ID || source.DSNGeneration != dsn.DSNGeneration {
			cause := corruptionf("source reciprocal DSN identity is invalid")

			qerr := q.quarantineDSNStage(path, id, "orphan", cause)
			if qerr != nil {
				q.recordQuarantineFailure(id, path, cause, qerr)
			}

			continue
		}

		readyDir := filepath.Join(q.ready, id)

		_, err = os.Stat(readyDir)
		if err == nil {
			existing, loadErr := q.loadAcceptedDir(readyDir, id)
			if loadErr == nil && sameDSNIdentity(existing, dsn) && existing.DSNSourceRevision == source.Revision {
				err = q.quarantineDir(path, id+"-dsn-duplicate")
				if err != nil {
					q.recordQuarantineFailure(id, path, corruptionf("duplicate ready DSN"), err)

					continue
				}

				q.Corrupt = append(q.Corrupt, fmt.Errorf("staged DSN %s: duplicate ready entry", id))

				continue
			}

			if loadErr != nil && !IsCorruption(loadErr) {
				q.recordTransientBlocked(id, path, fmt.Errorf("read existing ready DSN: %w", loadErr))
				q.recordTransientBlocked(source.ID, sourceDir, fmt.Errorf("linked DSN %s ready read failed", id))

				continue
			}

			cause := corruptionf("ready DSN collision: %v", ErrIDConflict)

			err = q.quarantineDSNStage(path, id, "collision", cause)
			if err != nil {
				q.recordQuarantineFailure(id, path, cause, err)
			}

			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			q.recordTransientBlocked(id, path, fmt.Errorf("inspect ready DSN: %w", err))
			q.recordTransientBlocked(source.ID, filepath.Join(q.ready, source.ID), fmt.Errorf("linked DSN %s could not be inspected", id))

			continue
		}

		moved, err := moveState(path, readyDir)
		if err != nil {
			q.recordTransientBlocked(id, path, fmt.Errorf("publish recovered DSN (moved=%t): %w", moved, err))
			q.recordTransientBlocked(source.ID, filepath.Join(q.ready, source.ID), fmt.Errorf("linked DSN %s publication is unresolved", id))

			continue
		}
	}

	return nil
}

func (q *Queue) blockLinkedSource(dsnID string, cause error) {
	entries, err := os.ReadDir(q.ready)
	if err != nil {
		q.Warnings = append(q.Warnings, fmt.Errorf("inspect source for staged DSN %s: %w", dsnID, err))

		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		sourceDir := filepath.Join(q.ready, entry.Name())

		source, err := q.loadAcceptedDir(sourceDir, entry.Name())
		if err != nil {
			if !IsCorruption(err) {
				q.recordTransientBlocked(entry.Name(), sourceDir, fmt.Errorf("inspect possible source for staged DSN %s: %w", dsnID, err))
			}

			continue
		}

		if source.DSNID != dsnID {
			continue
		}

		q.recordTransientBlocked(source.ID, sourceDir, fmt.Errorf("linked staged DSN %s could not be read: %w", dsnID, cause))
	}
}

func (q *Queue) quarantineDSNStage(stage, id, suffix string, cause error) error {
	if !IsCorruption(cause) {
		return errors.New("refusing to quarantine DSN stage without typed corruption")
	}

	entries, err := os.ReadDir(q.ready)
	if err != nil {
		return err
	}

	var linked []*Envelope

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		sourceDir := filepath.Join(q.ready, entry.Name())

		source, err := q.loadAcceptedDir(sourceDir, entry.Name())
		if err != nil {
			if !IsCorruption(err) {
				for _, candidate := range entries {
					if !candidate.IsDir() {
						continue
					}

					candidateDir := filepath.Join(q.ready, candidate.Name())
					q.recordTransientBlocked(candidate.Name(), candidateDir, fmt.Errorf("source scan for corrupt staged DSN %s is incomplete: %w", id, err))
				}

				return fmt.Errorf("%w: source %s: %v", errDSNSourceScanIncomplete, entry.Name(), err)
			}

			continue
		}

		if source.DSNID != id {
			continue
		}

		linked = append(linked, source)
	}

	for _, source := range linked {
		sourceDir := filepath.Join(q.ready, source.ID)

		err = q.quarantineDir(sourceDir, source.ID+"-dsn-source")
		if err != nil {
			q.recordQuarantineFailure(source.ID, sourceDir, fmt.Errorf("linked staged DSN %s is invalid", id), err)

			continue
		}

		q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: linked staged DSN %s is invalid", source.ID, id))
	}

	err = q.quarantineDir(stage, id+"-dsn-"+suffix)
	if err != nil {
		return err
	}

	q.Corrupt = append(q.Corrupt, fmt.Errorf("staged DSN %s: %w", id, cause))

	return nil
}

func (q *Queue) loadReady() error {
	entries, err := os.ReadDir(q.ready)
	if err != nil {
		return err
	}

	for _, e := range entries {
		_, blocked := q.blocked[e.Name()]
		if blocked {
			continue
		}

		if !e.IsDir() {
			// stray file
			err = q.quarantineFile(filepath.Join(q.ready, e.Name()), e.Name()+"-stray")
			if err != nil {
				q.recordQuarantineFailure(e.Name(), filepath.Join(q.ready, e.Name()), corruptionf("stray file in ready"), err)
				continue
			}

			q.Corrupt = append(q.Corrupt, fmt.Errorf("stray file in ready: %s", e.Name()))

			continue
		}

		id := e.Name()
		dir := filepath.Join(q.ready, id)

		err = ValidateID(id)
		if err != nil {
			err = corruptionf("invalid ready id: %v", err)

			qerr := q.quarantineDir(dir, "badid-"+sanitize(id))
			if qerr != nil {
				q.recordQuarantineFailure(id, dir, err, qerr)

				continue
			}

			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: %w", id, err))

			continue
		}

		err = acceptedDir(dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				err = corruptionf("queue entry is missing acceptance state")
			}

			if !IsCorruption(err) {
				q.recordTransientBlocked(id, dir, fmt.Errorf("read acceptance state: %w", err))

				continue
			}

			qerr := q.quarantineDir(dir, id)
			if qerr != nil {
				q.recordQuarantineFailure(id, dir, fmt.Errorf("read add state: %w", err), qerr)

				continue
			}

			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: read add state: %w", id, err))

			continue
		}

		stagedMeta := filepath.Join(dir, reviveMetaName)

		_, err = os.Stat(stagedMeta)
		if err == nil {
			moved, moveErr := moveState(stagedMeta, filepath.Join(dir, metaName))
			if moveErr != nil && !moved {
				q.recordTransientBlocked(id, dir, fmt.Errorf("complete revive: %w", moveErr))

				continue
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			q.recordTransientBlocked(id, dir, fmt.Errorf("inspect revive: %w", err))

			continue
		}

		env, err := q.loadDir(dir, id)
		if err != nil {
			if !IsCorruption(err) {
				q.recordTransientBlocked(id, dir, fmt.Errorf("read ready entry: %w", err))

				continue
			}

			qerr := q.quarantineDir(dir, id)
			if qerr != nil {
				q.recordQuarantineFailure(id, dir, err, qerr)

				continue
			}

			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: %w", id, err))

			continue
		}

		deadDir := filepath.Join(q.dead, id)

		dead, deadErr := q.loadAcceptedDir(deadDir, id)
		if deadErr == nil {
			if dead.Incarnation != env.Incarnation || dead.Revision != env.Revision {
				q.recordBlocked(id, dir, fmt.Errorf("%w: ready and dead entries differ", ErrIDConflict))

				continue
			}

			qerr := q.quarantineDir(dir, id+"-dead-duplicate")
			if qerr != nil {
				q.recordQuarantineFailure(id, dir, corruptionf("duplicate dead-letter entry"), qerr)

				continue
			}

			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: duplicate dead-letter entry", id))

			continue
		}

		if !errors.Is(deadErr, os.ErrNotExist) {
			if !IsCorruption(deadErr) {
				q.recordTransientBlocked(id, deadDir, fmt.Errorf("read colliding dead entry: %w", deadErr))

				continue
			}

			qerr := q.quarantineDir(deadDir, id+"-invalid-dead")
			if qerr != nil {
				q.recordQuarantineFailure(id, deadDir, deadErr, qerr)

				continue
			}

			q.Corrupt = append(q.Corrupt, fmt.Errorf("dead %s: %w", id, deadErr))
		}

		if !q.noteAddedLocked(env) {
			cause := corruptionf("queue accounting overflow")

			qerr := q.quarantineDir(dir, id+"-accounting-overflow")
			if qerr != nil {
				q.recordQuarantineFailure(id, dir, cause, qerr)

				continue
			}

			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: queue accounting overflow", id))

			continue
		}

		q.scheduleLocked(env)
	}

	return nil
}
