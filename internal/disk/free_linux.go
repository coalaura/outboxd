//go:build linux

package disk

import (
	"fmt"
	"syscall"
)

// FreeBytes reports the number of free bytes available to a non-root caller
// on the filesystem that contains path.
func FreeBytes(path string) (int64, error) {
	var st syscall.Statfs_t

	err := syscall.Statfs(path, &st)
	if err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}

	// Frsize is the allocation unit used by the block counts.
	blockSize := int64(st.Frsize)
	if blockSize <= 0 {
		blockSize = int64(st.Bsize)
	}

	return availableBytes(path, uint64(st.Bavail), blockSize)
}
