//go:build !windows

package disk

import (
	"os"
)

// Sync flushes a directory entry so renames survive a crash.
func Sync(path string) error {
	h := currentHooks()

	if h.BeforeSyncDir != nil {
		err := h.BeforeSyncDir(path)
		if err != nil {
			return err
		}
	}

	directory, err := os.Open(path)
	if err != nil {
		return err
	}

	defer directory.Close()

	err = directory.Sync()

	if err != nil {
		return err
	}

	h = currentHooks()

	if h.AfterSyncDir != nil {
		return h.AfterSyncDir(path)
	}

	return nil
}
