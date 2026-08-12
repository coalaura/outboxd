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

// DeadIDs lists dead-letter entry IDs.
func (q *Queue) DeadIDs() ([]string, error) {
	err := q.beginOperation()
	if err != nil {
		return nil, err
	}

	defer q.endOperation()
	entries, err := os.ReadDir(q.dead)
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

// DeleteDead crash-safely moves a dead letter through trash before deletion.
func (q *Queue) DeleteDead(id string) error {
	err := ValidateID(id)
	if err != nil {
		return err
	}

	err = q.beginTransition(id)
	if err != nil {
		return err
	}

	defer q.endTransition(id)

	return q.deleteStored(q.dead, id, id)
}

// LoadDead reads a dead-letter envelope by id.
func (q *Queue) LoadDead(id string) (*Envelope, error) {
	err := q.beginOperation()
	if err != nil {
		return nil, err
	}

	defer q.endOperation()

	err = ValidateID(id)
	if err != nil {
		return nil, err
	}

	return q.loadAcceptedDir(filepath.Join(q.dead, id), id)
}

// ExportDead copies the original message to w.
func (q *Queue) ExportDead(id string, w io.Writer) error {
	err := q.beginOperation()
	if err != nil {
		return err
	}

	defer q.endOperation()

	err = ValidateID(id)
	if err != nil {
		return err
	}

	dir := filepath.Join(q.dead, id)

	env, f, err := q.openAcceptedBody(dir, id)
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
