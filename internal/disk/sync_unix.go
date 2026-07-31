//go:build !windows

package disk

import (
	"os"
)

// Sync flushes a directory entry so renames survive a crash.
func Sync(path string) error {
	if h := currentHooks(); h.BeforeSyncDir != nil {
		if err := h.BeforeSyncDir(path); err != nil {
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
	if h := currentHooks(); h.AfterSyncDir != nil {
		return h.AfterSyncDir(path)
	}
	return nil
}
