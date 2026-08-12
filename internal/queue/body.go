package queue

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type trackedReader struct {
	file      *os.File
	queue     *Queue
	remaining int64
	digest    string
	hash      hash.Hash
	verified  bool
	once      sync.Once
	err       error
}

func (r *trackedReader) Read(p []byte) (int, error) {
	if r.verified {
		return 0, io.EOF
	}

	if r.remaining == 0 {
		var extra [1]byte

		n, err := r.file.Read(extra[:])
		if n != 0 {
			return 0, corruptionf("body size mismatch while reading: body grew")
		}

		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}

		actual := bodyDigestPrefix + hex.EncodeToString(r.hash.Sum(nil))
		if actual != r.digest {
			return 0, corruptionf("body digest mismatch: metadata=%s actual=%s", r.digest, actual)
		}

		r.verified = true

		return 0, io.EOF
	}

	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}

	n, err := r.file.Read(p)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])

		r.remaining -= int64(n)
	}

	if errors.Is(err, io.EOF) && r.remaining != 0 {
		return n, corruptionf("body size mismatch while reading: %d bytes missing", r.remaining)
	}

	return n, err
}

func (r *trackedReader) Close() error {
	r.once.Do(func() {
		r.err = r.file.Close()

		r.queue.endOperation()
	})

	return r.err
}

// Reader opens the stored message body for a ready entry.
func (q *Queue) Reader(id string) (io.ReadCloser, error) {
	err := q.beginOperation()
	if err != nil {
		return nil, err
	}

	owned := true

	defer func() {
		if owned {
			q.endOperation()
		}
	}()

	err = ValidateID(id)
	if err != nil {
		return nil, err
	}

	dir := filepath.Join(q.ready, id)

	env, file, err := q.openAcceptedBody(dir, id)
	if err != nil {
		return nil, err
	}

	owned = false

	return &trackedReader{
		file:      file,
		queue:     q,
		remaining: env.Size,
		digest:    env.BodyDigest,
		hash:      sha256.New(),
	}, nil
}

// ReadBody returns the full body bytes for ready or dead.
func (q *Queue) ReadBody(id string) ([]byte, error) {
	err := q.beginOperation()
	if err != nil {
		return nil, err
	}

	defer q.endOperation()

	err = ValidateID(id)
	if err != nil {
		return nil, err
	}

	ready := filepath.Join(q.ready, id)

	env, file, err := q.openAcceptedBody(ready, id)
	if err == nil {
		defer file.Close()

		if q.afterBodyVerify != nil {
			q.afterBodyVerify()
		}

		return readBodyFromFile(file, env.Size, env.BodyDigest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	dead := filepath.Join(q.dead, id)

	env, file, err = q.openAcceptedBody(dead, id)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	if q.afterBodyVerify != nil {
		q.afterBodyVerify()
	}

	return readBodyFromFile(file, env.Size, env.BodyDigest)
}

func (q *Queue) openBody(path string, expected int64, digest string) (*os.File, error) {
	file, info, err := openRegular(path)
	if err != nil {
		return nil, err
	}

	if info.Size() != expected {
		file.Close()

		return nil, corruptionf("body size mismatch: metadata=%d actual=%d", expected, info.Size())

	}

	if q.afterBodyOpen != nil {
		q.afterBodyOpen()
	}

	info, err = file.Stat()
	if err != nil {
		file.Close()

		return nil, err
	}

	if !info.Mode().IsRegular() || info.Size() != expected {
		file.Close()

		return nil, corruptionf("body size mismatch: metadata=%d actual=%d", expected, info.Size())
	}

	err = verifyBodyHandle(file, expected, digest)
	if err != nil {
		file.Close()

		return nil, err
	}

	return file, nil

}

func (q *Queue) openAcceptedBody(dir, expectID string) (*Envelope, *os.File, error) {
	env, err := loadAcceptedMetadata(dir, expectID)
	if err != nil {
		return nil, nil, err
	}

	file, err := q.openBody(filepath.Join(dir, bodyName), env.Size, env.BodyDigest)
	if err != nil {
		return nil, nil, err
	}

	return env, file, nil
}

func readBodyFromFile(file *os.File, expected int64, digest string) ([]byte, error) {
	var body bytes.Buffer

	hash := sha256.New()

	err := copyExactBody(io.MultiWriter(&body, hash), file, expected)
	if err != nil {
		return nil, err
	}

	actual := bodyDigestPrefix + hex.EncodeToString(hash.Sum(nil))
	if actual != digest {
		return nil, corruptionf("body digest mismatch: metadata=%s actual=%s", digest, actual)
	}

	return body.Bytes(), nil
}

func copyExactBody(dst io.Writer, file *os.File, expected int64) error {
	limit, ok := checkedAddInt64(expected, 1)
	if !ok {
		return errors.New("body size is too large")
	}

	written, err := io.Copy(dst, io.LimitReader(file, limit))
	if err != nil {
		return err
	}

	if written != expected {
		return corruptionf("body size mismatch while reading: metadata=%d actual=%d", expected, written)
	}

	info, err := file.Stat()
	if err != nil {
		return err
	}

	if !info.Mode().IsRegular() || info.Size() != expected {
		return corruptionf("body size mismatch while reading: metadata=%d actual=%d", expected, info.Size())
	}

	return nil
}

func bodyDigest(body []byte) string {
	sum := sha256.Sum256(body)

	return bodyDigestPrefix + hex.EncodeToString(sum[:])
}

func verifyBodyHandle(file *os.File, expected int64, digest string) error {
	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	hash := sha256.New()

	err = copyExactBody(hash, file, expected)
	if err != nil {
		return err
	}

	actual := bodyDigestPrefix + hex.EncodeToString(hash.Sum(nil))
	if actual != digest {
		return corruptionf("body digest mismatch: metadata=%s actual=%s", digest, actual)
	}

	_, err = file.Seek(0, io.SeekStart)
	return err
}
