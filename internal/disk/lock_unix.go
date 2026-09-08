//go:build !windows

package disk

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type unixFileLock struct {
	f *os.File
}

// Lock acquires an exclusive, non-blocking flock on path, creating the file if
// needed. The returned FileLock must stay open for the duration of the lock.
func Lock(path string) (*FileLock, error) {
	return lockUnix(path, 0)
}

// LockForRepair acquires a lock without requiring its existing permissions to
// be valid. It is reserved for the explicit permission-repair operation.
func LockForRepair(path string) (*FileLock, error) {
	return lockUnix(path, unix.O_NOFOLLOW)
}

func lockUnix(path string, extraFlags int) (*FileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|extraFlags, 0600)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()

		return nil, err
	}

	if !info.Mode().IsRegular() {
		_ = f.Close()

		return nil, fmt.Errorf("lock %s is not a regular file", path)
	}

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err != nil {
		_ = f.Close()

		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLocked
		}

		return nil, fmt.Errorf("flock %s: %w", path, err)
	}

	return &FileLock{impl: &unixFileLock{f: f}}, nil
}
func (l *unixFileLock) close() error {
	if l.f == nil {
		return nil
	}

	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)

	err := l.f.Close()

	l.f = nil

	return err
}
