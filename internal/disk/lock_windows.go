//go:build windows

package disk

import (
	"errors"
	"fmt"
	"os"

	"github.com/coalaura/outboxd/internal/windowsacl"
	"golang.org/x/sys/windows"
)

type winFileLock struct {
	f *os.File
}

// Lock acquires an exclusive, non-blocking byte-range lock on path, creating
// the file if needed. The returned FileLock must stay open for the lock's life.
func Lock(path string) (*FileLock, error) {
	var f *os.File
	var err error

	for {
		f, err = os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			err = windowsacl.ValidateHandle(windows.Handle(f.Fd()), path, true, false)
			if err != nil {
				_ = f.Close()

				return nil, err
			}

			break
		}

		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		f, err = createPrivateFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			break
		}

		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
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

	return &FileLock{impl: &winFileLock{f: f}}, nil
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
