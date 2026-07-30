//go:build !windows

package disk

import (
	"fmt"
	"syscall"
)

// FreeBytes reports the number of free bytes available to a non-root caller
// on the filesystem that contains path.
func FreeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	// Bavail is free blocks for unprivileged users.
	bsize := int64(st.Bsize)
	if bsize <= 0 {
		bsize = int64(st.Frsize)
	}
	if bsize <= 0 {
		return 0, fmt.Errorf("statfs %s: invalid block size", path)
	}
	return int64(st.Bavail) * bsize, nil
}
