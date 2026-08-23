package queue

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/coalaura/outboxd/internal/disk"
)

type trackedReader struct {
	file      *os.File
	reader    io.Reader
	queue     *Queue
	remaining int64
	digest    string
	hash      hash.Hash
	whole     bool
	verified  bool
	once      sync.Once
	err       error
}

func (r *trackedReader) Read(p []byte) (int, error) {
	if r.verified {
		return 0, io.EOF
	}

	if r.remaining == 0 {
		if r.whole {
			var extra [1]byte

			n, err := r.file.Read(extra[:])
			if n != 0 {
				return 0, corruptionf("body size mismatch while reading: body grew")
			}

			if err != nil && !errors.Is(err, io.EOF) {
				return 0, err
			}
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

	n, err := r.reader.Read(p)
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
	return q.ReaderVariant(id, 0)
}

// ReaderVariant opens one immutable message variant for a ready entry.
func (q *Queue) ReaderVariant(id string, bodyIndex int) (io.ReadCloser, error) {
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

	var (
		reader    io.Reader = file
		remaining           = env.Size
		digest              = env.BodyDigest
		whole               = true
	)

	if len(env.Bodies) != 0 {
		if bodyIndex < 0 || bodyIndex >= len(env.Bodies) {
			file.Close()

			return nil, errors.New("invalid message body index")
		}

		body := env.Bodies[bodyIndex]

		reader = io.NewSectionReader(file, body.Offset, body.Size)

		remaining = body.Size
		digest = body.Digest
		whole = false
	} else if bodyIndex != 0 {
		file.Close()

		return nil, errors.New("invalid message body index")
	}

	owned = false

	return &trackedReader{
		file:      file,
		reader:    reader,
		queue:     q,
		remaining: remaining,
		digest:    digest,
		hash:      sha256.New(),
		whole:     whole,
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

	var (
		env  *Envelope
		file *os.File
	)

	if q.readOnly {
		dir, openErr := q.openReadOnlyEntry(q.ready, id)
		if openErr == nil {
			env, file, err = q.openAcceptedBodyHandle(dir, id)

			dir.Close()
		} else {
			err = openErr
		}
	} else {
		env, file, err = q.openAcceptedBody(filepath.Join(q.ready, id), id)
	}

	if err == nil {
		defer file.Close()

		if q.afterBodyVerify != nil {
			q.afterBodyVerify()
		}

		body, readErr := readBodyFromFile(file, env.Size, env.BodyDigest)
		if readErr != nil {
			return nil, readErr
		}

		return firstBodyVariant(env, body)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if q.readOnly {
		dir, openErr := q.openReadOnlyEntry(q.dead, id)
		if openErr == nil {
			env, file, err = q.openAcceptedBodyHandle(dir, id)

			dir.Close()
		} else {
			err = openErr
		}
	} else {
		env, file, err = q.openAcceptedBody(filepath.Join(q.dead, id), id)
	}

	if err != nil {
		return nil, err
	}

	defer file.Close()

	if q.afterBodyVerify != nil {
		q.afterBodyVerify()
	}

	body, err := readBodyFromFile(file, env.Size, env.BodyDigest)
	if err != nil {
		return nil, err
	}

	return firstBodyVariant(env, body)
}

func firstBodyVariant(env *Envelope, data []byte) ([]byte, error) {
	if len(env.Bodies) == 0 {
		return data, nil
	}

	body := env.Bodies[0]

	data = data[body.Offset : body.Offset+body.Size]
	if bodyDigest(data) != body.Digest {
		return nil, corruptionf("message body digest mismatch")
	}

	return data, nil
}

func verifyBodyData(env *Envelope, data []byte) error {
	for i, body := range env.Bodies {
		variant := data[body.Offset : body.Offset+body.Size]
		if bodyDigest(variant) != body.Digest {
			return fmt.Errorf("body[%d]: digest does not match data", i)
		}
	}

	return nil
}

func (q *Queue) openBody(path string, env *Envelope) (*os.File, error) {
	file, info, err := openRegular(path)
	if err != nil {
		return nil, err
	}

	if info.Size() != env.Size {
		file.Close()

		return nil, corruptionf("body size mismatch: metadata=%d actual=%d", env.Size, info.Size())

	}

	if q.afterBodyOpen != nil {
		q.afterBodyOpen()
	}

	info, err = file.Stat()
	if err != nil {
		file.Close()

		return nil, err
	}

	if !info.Mode().IsRegular() || info.Size() != env.Size {
		file.Close()

		return nil, corruptionf("body size mismatch: metadata=%d actual=%d", env.Size, info.Size())
	}

	err = verifyEnvelopeBodyHandle(file, env)
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

	file, err := q.openBody(filepath.Join(dir, bodyName), env)
	if err != nil {
		return nil, nil, err
	}

	return env, file, nil
}

func (q *Queue) openAcceptedBodyHandle(dir *os.File, expectID string) (*Envelope, *os.File, error) {
	env, err := loadAcceptedMetadataHandle(dir, expectID)
	if err != nil {
		return nil, nil, err
	}

	file, info, err := disk.OpenRegularAt(dir, bodyName)
	if err != nil {
		return nil, nil, err
	}

	if info.Size() != env.Size {
		file.Close()

		return nil, nil, corruptionf("body size mismatch: metadata=%d actual=%d", env.Size, info.Size())
	}

	if q.afterBodyOpen != nil {
		q.afterBodyOpen()
	}

	err = verifyEnvelopeBodyHandle(file, env)
	if err != nil {
		file.Close()

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

func verifyEnvelopeBodyHandle(file *os.File, env *Envelope) error {
	if len(env.Bodies) == 0 {
		return verifyBodyHandle(file, env.Size, env.BodyDigest)
	}

	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	wholeHash := sha256.New()

	for i, body := range env.Bodies {
		variantHash := sha256.New()

		written, copyErr := io.CopyN(io.MultiWriter(wholeHash, variantHash), file, body.Size)
		if copyErr != nil {
			if !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, io.ErrUnexpectedEOF) {
				return copyErr
			}

			return corruptionf("body[%d] size mismatch while reading: metadata=%d actual=%d", i, body.Size, written)
		}

		if written != body.Size {
			return corruptionf("body[%d] size mismatch while reading: metadata=%d actual=%d", i, body.Size, written)
		}

		actual := bodyDigestPrefix + hex.EncodeToString(variantHash.Sum(nil))
		if actual != body.Digest {
			return corruptionf("body[%d] digest mismatch: metadata=%s actual=%s", i, body.Digest, actual)
		}
	}

	info, err := file.Stat()
	if err != nil {
		return err
	}

	if !info.Mode().IsRegular() || info.Size() != env.Size {
		return corruptionf("body size mismatch while reading: metadata=%d actual=%d", env.Size, info.Size())
	}

	actual := bodyDigestPrefix + hex.EncodeToString(wholeHash.Sum(nil))
	if actual != env.BodyDigest {
		return corruptionf("body digest mismatch: metadata=%s actual=%s", env.BodyDigest, actual)
	}

	_, err = file.Seek(0, io.SeekStart)
	return err
}
