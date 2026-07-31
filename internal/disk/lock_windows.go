//go:build windows

package disk

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Lock acquires an exclusive, non-blocking byte-range lock on path, creating
// the file if needed. The returned FileLock must stay open for the lock's life.
func Lock(path string) (*FileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	var ol windows.Overlapped
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&ol,
	)
	if err != nil {
		_ = f.Close()
		if err == windows.ERROR_LOCK_VIOLATION || err == windows.ERROR_IO_PENDING {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("LockFileEx %s: %w", path, err)
	}
	return &FileLock{path: path, impl: &winFileLock{f: f}}, nil
}

type winFileLock struct {
	f *os.File
}

func (l *winFileLock) close() error {
	if l.f == nil {
		return nil
	}
	var ol windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, &ol)
	err := l.f.Close()
	l.f = nil
	return err
}
