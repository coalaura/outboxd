package queue

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
)

// ReadyIDs lists entries awaiting delivery.
func (q *Queue) ReadyIDs() ([]string, error) {
	return q.storedIDs(q.ready)
}

// DeadIDs lists dead-letter entry IDs.
func (q *Queue) DeadIDs() ([]string, error) {
	return q.storedIDs(q.dead)
}

func (q *Queue) storedIDs(namespace string) ([]string, error) {
	err := q.beginOperation()
	if err != nil {
		return nil, err
	}

	defer q.endOperation()

	var entries []os.DirEntry

	if q.readOnly {
		dir, openErr := q.readOnlyNamespace(namespace)
		if openErr != nil {
			return nil, openErr
		}

		defer dir.Close()

		entries, err = dir.ReadDir(-1)
	} else {
		entries, err = os.ReadDir(namespace)
	}

	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(entries))

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		err = ValidateID(e.Name())
		if err != nil {
			continue
		}

		ids = append(ids, e.Name())
	}

	return ids, nil
}

// LoadReady reads an accepted envelope awaiting delivery.
func (q *Queue) LoadReady(id string) (*Envelope, error) {
	return q.loadStored(q.ready, id)
}

// DeleteDead crash-safely moves a dead letter through trash before deletion.
func (q *Queue) DeleteDead(id string) error {
	err := q.beginOperation()
	if err != nil {
		return err
	}

	defer q.endOperation()

	err = q.rejectReadOnly()
	if err != nil {
		return err
	}

	err = ValidateID(id)
	if err != nil {
		return err
	}

	err = q.beginTransition(id)
	if err != nil {
		return err
	}

	var linkedDSNID string

	defer func() {
		q.endTransitions(id, linkedDSNID)
	}()

	err = q.startMutation()
	if err != nil {
		return err
	}

	defer q.finishMutation()

	envelope, err := q.loadAcceptedDir(filepath.Join(q.dead, id), id)
	if err != nil {
		return err
	}

	linkedDSNID, err = q.claimLinkedDeadDSN(envelope)
	if err != nil {
		return err
	}

	return q.deleteStoredLocked(q.dead, id, id)
}

// LoadDead reads a dead-letter envelope by id.
func (q *Queue) LoadDead(id string) (*Envelope, error) {
	return q.loadStored(q.dead, id)
}

func (q *Queue) loadStored(namespace, id string) (*Envelope, error) {
	err := q.beginOperation()
	if err != nil {
		return nil, err
	}

	defer q.endOperation()

	err = ValidateID(id)
	if err != nil {
		return nil, err
	}

	if q.readOnly {
		dir, err := q.openReadOnlyEntry(namespace, id)
		if err != nil {
			return nil, err
		}

		defer dir.Close()

		return q.loadAcceptedHandle(dir, id)
	}

	return q.loadAcceptedDir(filepath.Join(namespace, id), id)
}

// ExportReady copies the original queued message to w.
func (q *Queue) ExportReady(id string, w io.Writer) error {
	return q.exportStored(q.ready, id, w)
}

// ExportDead copies the original message to w.
func (q *Queue) ExportDead(id string, w io.Writer) error {
	return q.exportStored(q.dead, id, w)
}

func (q *Queue) exportStored(namespace, id string, w io.Writer) error {
	err := q.beginOperation()
	if err != nil {
		return err
	}

	defer q.endOperation()

	err = ValidateID(id)
	if err != nil {
		return err
	}

	var (
		env *Envelope
		f   *os.File
	)

	if q.readOnly {
		dir, openErr := q.openReadOnlyEntry(namespace, id)
		if openErr != nil {
			return openErr
		}

		defer dir.Close()

		env, f, err = q.openAcceptedBodyHandle(dir, id)
	} else {
		env, f, err = q.openAcceptedBody(filepath.Join(namespace, id), id)
	}

	if err != nil {
		return err
	}

	defer f.Close()

	if q.afterBodyVerify != nil {
		q.afterBodyVerify()
	}

	body, err := readBodyFromFile(f, env.Size, env.BodyDigest)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, bytes.NewReader(body))
	return err
}

func (q *Queue) readOnlyNamespace(namespace string) (*os.File, error) {
	if namespace == q.ready && q.readyDir != nil {
		return disk.DuplicateDirectory(q.readyDir)
	}

	if namespace == q.dead && q.deadDir != nil {
		return disk.DuplicateDirectory(q.deadDir)
	}

	return nil, os.ErrNotExist
}

func (q *Queue) openReadOnlyEntry(namespace, id string) (*os.File, error) {
	parent, err := q.readOnlyNamespace(namespace)
	if err != nil {
		return nil, err
	}

	defer parent.Close()

	return disk.OpenDirectoryAt(parent, id)
}

// RetryReady makes an accepted ready entry immediately eligible for another
// delivery attempt while preserving its attempt and recipient history. The
// caller must own the queue exclusively for maintenance, without workers.
func (q *Queue) RetryReady(id string) (*Envelope, error) {
	envelope, err := q.LoadReady(id)
	if err != nil {
		return nil, err
	}

	q.mu.Lock()
	if queued := q.scheduled[id]; queued != nil {
		q.pending.Remove(queued)

		delete(q.scheduled, id)
	}
	q.mu.Unlock()

	envelope.NextAttempt = time.Now()

	err = q.Retry(envelope)
	return envelope, err
}

// DeleteReady crash-safely deletes an entry awaiting delivery. The caller must
// own the queue exclusively for maintenance, without workers. Linked source
// messages and generated DSNs must complete through normal DSN recovery.
func (q *Queue) DeleteReady(id string) error {
	envelope, err := q.LoadReady(id)
	if err != nil {
		return err
	}

	if envelope.DSNID != "" || envelope.DSNSourceID != "" {
		return errors.New("refusing to delete a queue entry with linked DSN state")
	}

	q.mu.Lock()
	if queued := q.scheduled[id]; queued != nil {
		q.pending.Remove(queued)

		delete(q.scheduled, id)
	}
	q.mu.Unlock()

	err = q.Finish(envelope)
	if err != nil {
		q.Requeue(envelope)
	}

	return err
}

func (q *Queue) deleteStored(namespace, name, trashName string) error {
	err := q.beginOperation()
	if err != nil {
		return err
	}

	defer q.endOperation()

	err = q.rejectReadOnly()
	if err != nil {
		return err
	}

	err = q.startMutation()
	if err != nil {
		return err
	}

	defer q.finishMutation()

	return q.deleteStoredLocked(namespace, name, trashName)
}

func (q *Queue) deleteStoredLocked(namespace, name, trashName string) error {
	src := filepath.Join(namespace, name)

	_, err := os.Lstat(src)
	if err != nil {
		return err
	}

	entryBytes, _ := disk.AllocatedBytes(src)

	dst := filepath.Join(q.trash, trashName+"."+strconv.FormatInt(time.Now().UnixNano(), 10))

	moved, err := moveState(src, dst)
	if err != nil && !moved {
		return err
	}

	cleanupErr := q.removeTrash(dst)
	if cleanupErr != nil {
		return errors.Join(err, fmt.Errorf("%w: %w", ErrCleanup, cleanupErr))
	}

	q.removePhysical(entryBytes)

	return err
}

func validOpaqueName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsAny(name, `/\`)
}
