//go:build windows

package disk

// Sync is a no-op on Windows. Directory handles cannot be opened for writing.
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
