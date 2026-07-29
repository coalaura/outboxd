//go:build !windows

package disk

import (
	"errors"
	"os"
	"syscall"
)

// Sync flushes a directory entry so renames survive a crash.
func Sync(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}

	defer directory.Close()

	err = directory.Sync()

	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		return nil
	}

	return err
}
