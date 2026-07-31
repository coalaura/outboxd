//go:build windows

package disk

// Sync runs the directory-sync hooks on Windows. Durable directory creation
// and queue renames use MoveFileEx with MOVEFILE_WRITE_THROUGH instead because
// Windows does not permit FlushFileBuffers on a directory handle.
func Sync(path string) error {
	if h := currentHooks(); h.BeforeSyncDir != nil {
		if err := h.BeforeSyncDir(path); err != nil {
			return err
		}
	}
	if h := currentHooks(); h.AfterSyncDir != nil {
		return h.AfterSyncDir(path)
	}
	return nil
}
