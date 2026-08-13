package queue

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/coalaura/outboxd/internal/disk"
)

// storeReady reports whether an additional metadata temp file may remain.
func (q *Queue) storeReady(envelope *Envelope) (bool, error) {
	nextRevision, err := incrementRevision(envelope.Revision)
	if err != nil {
		return false, err
	}

	dir := filepath.Join(q.ready, envelope.ID)

	err = q.matchReady(envelope)
	if err != nil {
		return false, err
	}

	before, err := disk.AllocatedBytes(dir)
	if err != nil {
		return false, err
	}

	path := filepath.Join(dir, metaName)

	updated := *envelope

	updated.Revision = nextRevision

	err = validateEnvelope(&updated)
	if err != nil {
		return false, err
	}

	metadata, err := marshalEnvelope(&updated)
	if err != nil {
		return false, err
	}

	committed, retainedTemp, err := q.writeMetaReconciled(path, &updated)

	after, measureErr := disk.AllocatedBytes(dir)
	if measureErr == nil {
		q.adjustPhysicalDelta(before, after)

		retainedTemp = false // The complete entry measurement includes any temp.
	} else if committed || retainedTemp {
		q.mu.Lock()
		q.addPhysicalLocked(disk.AllocationSize(int64(len(metadata))) + disk.AllocationSize(0))
		q.mu.Unlock()

		retainedTemp = false

		err = errors.Join(err, fmt.Errorf("measure updated queue entry: %w", measureErr))
	}

	if !committed {
		return retainedTemp, err
	}

	envelope.Revision = updated.Revision

	q.mu.Lock()

	entry, exists := q.accounted[envelope.ID]
	if exists && entry.incarnation == envelope.Incarnation {
		entry.revision = envelope.Revision

		q.accounted[envelope.ID] = entry
	}

	q.mu.Unlock()

	return retainedTemp, err
}

func (q *Queue) matchReady(envelope *Envelope) error {
	dir := filepath.Join(q.ready, envelope.ID)

	err := acceptedDir(dir)
	if err != nil {
		return err
	}

	current, err := q.loadDir(dir, envelope.ID)
	if err != nil {
		return err
	}

	if current.Incarnation != envelope.Incarnation {
		return fmt.Errorf("%w: queue incarnation changed", ErrIDConflict)
	}

	if current.Revision != envelope.Revision {
		return fmt.Errorf("%w: queue metadata changed", ErrIDConflict)
	}

	if current.Size != envelope.Size || current.BodyDigest != envelope.BodyDigest {
		return fmt.Errorf("%w: queue body identity changed", ErrIDConflict)
	}

	return nil
}

func (q *Queue) writeMeta(path string, envelope *Envelope) error {
	body, err := marshalEnvelope(envelope)
	if err != nil {
		return err
	}

	return disk.Write(path, body, 0600)
}

func (q *Queue) writeMetaReconciled(path string, envelope *Envelope) (bool, bool, error) {
	body, err := marshalEnvelope(envelope)
	if err != nil {
		return false, false, err
	}

	retainedTemp, err := disk.WriteWithTempState(path, body, 0600)
	if err != nil {
		visible, readErr := readBoundedRegular(path, maxEnvelopeMetadata)
		if readErr == nil && bytes.Equal(visible, body) {
			return true, retainedTemp, err
		}

		return false, retainedTemp, errors.Join(err, readErr)
	}

	return true, false, nil
}

func (q *Queue) loadDir(dir, expectID string) (*Envelope, error) {
	env, err := loadEnvelopeMetadata(dir, expectID)
	if err != nil {
		return nil, err
	}

	file, info, err := openRegular(filepath.Join(dir, bodyName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, corruptionf("missing body: %v", err)
		}

		return nil, fmt.Errorf("missing body: %w", err)
	}

	defer file.Close()

	if info.Size() != env.Size {
		return nil, corruptionf("body size mismatch: metadata=%d actual=%d", env.Size, info.Size())
	}

	err = verifyBodyHandle(file, env.Size, env.BodyDigest)
	if err != nil {
		return nil, err
	}

	return env, nil
}

func (q *Queue) loadAcceptedDir(dir, expectID string) (*Envelope, error) {
	env, err := loadAcceptedMetadata(dir, expectID)
	if err != nil {
		return nil, err
	}

	file, info, err := openRegular(filepath.Join(dir, bodyName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, corruptionf("missing body: %v", err)
		}

		return nil, fmt.Errorf("missing body: %w", err)
	}

	defer file.Close()

	if info.Size() != env.Size {
		return nil, corruptionf("body size mismatch: metadata=%d actual=%d", env.Size, info.Size())
	}

	err = verifyBodyHandle(file, env.Size, env.BodyDigest)
	if err != nil {
		return nil, err
	}

	return env, nil
}

func (q *Queue) loadAcceptedHandle(dir *os.File, expectID string) (*Envelope, error) {
	env, err := loadAcceptedMetadataHandle(dir, expectID)
	if err != nil {
		return nil, err
	}

	file, info, err := disk.OpenRegularAt(dir, bodyName)
	if err != nil {
		return nil, fmt.Errorf("missing body: %w", err)
	}

	defer file.Close()

	if info.Size() != env.Size {
		return nil, corruptionf("body size mismatch: metadata=%d actual=%d", env.Size, info.Size())
	}

	err = verifyBodyHandle(file, env.Size, env.BodyDigest)
	if err != nil {
		return nil, err
	}

	return env, nil
}

func (q *Queue) removeTrash(path string) error {
	removeErr := disk.RemoveAll(path)
	syncErr := disk.Sync(q.trash)

	return errors.Join(removeErr, syncErr)
}

// moveState reports whether the rename changed the live namespace even when a
// post-rename hook or parent sync returns an error.
func moveState(src, dst string) (bool, error) {
	err := disk.Rename(src, dst)
	if err == nil {
		return true, nil
	}

	_, srcErr := os.Stat(src)
	_, dstErr := os.Stat(dst)

	if errors.Is(srcErr, os.ErrNotExist) && dstErr == nil {
		return true, err
	}

	return false, err
}

func removeAndSync(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return disk.Sync(filepath.Dir(path))
}

func loadEnvelopeMetadata(dir, expectID string) (*Envelope, error) {
	metaPath := filepath.Join(dir, metaName)

	raw, err := readBoundedRegular(metaPath, maxEnvelopeMetadata)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, corruptionf("missing metadata: %v", err)
		}

		return nil, err
	}

	return decodeEnvelopeMetadata(raw, expectID)
}

func loadEnvelopeMetadataHandle(dir *os.File, expectID string) (*Envelope, error) {
	raw, err := readBoundedRegularAt(dir, metaName, maxEnvelopeMetadata)
	if err != nil {
		return nil, err
	}

	return decodeEnvelopeMetadata(raw, expectID)
}

func decodeEnvelopeMetadata(raw []byte, expectID string) (*Envelope, error) {
	env := new(Envelope)

	err := json.Unmarshal(raw, env)
	if err != nil {
		return nil, corruptionf("invalid json: %v", err)
	}

	if env.ID != expectID {
		return nil, corruptionf("id %q != directory %q", env.ID, expectID)
	}

	err = ValidateID(env.ID)
	if err != nil {
		return nil, corruptionf("invalid stored id: %v", err)
	}

	err = validateEnvelope(env)
	if err != nil {
		return nil, corruptionf("invalid envelope: %v", err)
	}

	return env, nil
}

func marshalEnvelope(envelope *Envelope) ([]byte, error) {
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	if len(body) > maxEnvelopeMetadata {
		return nil, fmt.Errorf("envelope metadata exceeds %d bytes", maxEnvelopeMetadata)
	}

	return body, nil
}

func readBoundedRegular(path string, max int64) ([]byte, error) {
	err := disk.CheckRead(path)
	if err != nil {
		return nil, err
	}

	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}

	if !before.Mode().IsRegular() {
		return nil, corruptionf("queue metadata is not a regular file")
	}

	if before.Size() > max {
		return nil, corruptionf("queue metadata exceeds %d bytes", max)
	}

	file, _, err := openRegularFromInfo(path, before)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	raw, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}

	if int64(len(raw)) > max {
		return nil, corruptionf("queue metadata exceeds %d bytes", max)
	}

	return raw, nil
}

func readBoundedRegularAt(dir *os.File, name string, max int64) ([]byte, error) {
	path := filepath.Join(dir.Name(), name)

	err := disk.CheckRead(path)
	if err != nil {
		return nil, err
	}

	file, info, err := disk.OpenRegularAt(dir, name)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	if info.Size() > max {
		return nil, corruptionf("queue metadata exceeds %d bytes", max)
	}

	raw, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}

	if int64(len(raw)) > max {
		return nil, corruptionf("queue metadata exceeds %d bytes", max)
	}

	return raw, nil
}

func openRegular(path string) (*os.File, os.FileInfo, error) {
	err := disk.CheckRead(path)
	if err != nil {
		return nil, nil, err
	}

	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}

	return openRegularFromInfo(path, before)
}

func openRegularFromInfo(path string, before os.FileInfo) (*os.File, os.FileInfo, error) {
	if !before.Mode().IsRegular() {
		return nil, nil, corruptionf("queue file is not a regular file")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	after, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}

	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		file.Close()

		return nil, nil, corruptionf("queue file changed while opening")
	}

	return file, after, nil
}

func loadAcceptedMetadata(dir, expectID string) (*Envelope, error) {
	err := acceptedDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, statErr := os.Stat(dir)
			if statErr == nil {
				return nil, corruptionf("queue entry is missing accepted state")
			} else {
				return nil, statErr
			}
		}

		return nil, err
	}

	return loadEnvelopeMetadata(dir, expectID)
}

func loadAcceptedMetadataHandle(dir *os.File, expectID string) (*Envelope, error) {
	state, err := readBoundedRegularAt(dir, addStateName, maxAddStateBytes)
	if err != nil {
		return nil, err
	}

	if string(state) != addAccepted {
		return nil, corruptionf("queue entry is not accepted")
	}

	return loadEnvelopeMetadataHandle(dir, expectID)
}

func acceptedDir(dir string) error {
	state, err := readBoundedRegular(filepath.Join(dir, addStateName), maxAddStateBytes)
	if err != nil {
		return err
	}

	if string(state) != addAccepted {
		return corruptionf("queue entry is not accepted")
	}

	return nil
}

func ensureDurableDir(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return &os.PathError{Op: "mkdir", Path: path, Err: os.ErrExist}
		}

		return nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return disk.MkdirDurable(path)
}
