//go:build !windows

package disk

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Lock acquires an exclusive, non-blocking flock on path, creating the file if
// needed. The returned FileLock must stay open for the duration of the lock.
func Lock(path string) (*FileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if err == unix.EWOULDBLOCK || err == unix.EAGAIN {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("flock %s: %w", path, err)
	}
	return &FileLock{path: path, impl: &unixFileLock{f: f}}, nil
}

type unixFileLock struct {
	f *os.File
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
