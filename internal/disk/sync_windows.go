//go:build windows

package disk

// Sync is a no-op on Windows. Directory handles cannot be opened for writing.
func Sync(_ string) error {
	return nil
}
