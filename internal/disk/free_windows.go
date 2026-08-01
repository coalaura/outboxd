//go:build windows

package disk

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// FreeBytes reports the number of free bytes available to the caller on the
// volume that contains path.
func FreeBytes(path string) (int64, error) {
	var (
		freeBytesAvailable     uint64
		totalNumberOfBytes     uint64
		totalNumberOfFreeBytes uint64
	)

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	err = windows.GetDiskFreeSpaceEx(
		pathPtr,
		&freeBytesAvailable,
		&totalNumberOfBytes,
		&totalNumberOfFreeBytes,
	)
	if err != nil {
		return 0, fmt.Errorf("GetDiskFreeSpaceEx %s: %w", path, err)
	}

	const maxInt64 = 1<<63 - 1

	if freeBytesAvailable > maxInt64 {
		return maxInt64, nil
	}

	return int64(freeBytesAvailable), nil
}
