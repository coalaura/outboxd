//go:build darwin || freebsd

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

	return availableBytes(path, uint64(st.Bavail), int64(st.Bsize))
}
