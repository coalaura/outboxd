//go:build windows

package disk

// Sync runs the directory-sync hooks on Windows. Durable directory creation
// and queue renames use MoveFileEx with MOVEFILE_WRITE_THROUGH instead because
// Windows does not permit FlushFileBuffers on a directory handle.
func Sync(path string) error {
	h := currentHooks()

	if h.BeforeSyncDir != nil {
		err := h.BeforeSyncDir(path)
		if err != nil {
			return err
		}
	}

	h = currentHooks()

	if h.AfterSyncDir != nil {
		return h.AfterSyncDir(path)
	}

	return nil
}
