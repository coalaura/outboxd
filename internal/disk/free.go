//go:build linux || darwin || freebsd || windows

package disk

import (
	"fmt"
	"math"
)

func availableBytes(path string, blocks uint64, blockSize int64) (int64, error) {
	if blockSize <= 0 {
		return 0, fmt.Errorf("free space %s: invalid block size", path)
	}

	if blocks > uint64(math.MaxInt64)/uint64(blockSize) {
		return math.MaxInt64, nil
	}

	return int64(blocks * uint64(blockSize)), nil
}
