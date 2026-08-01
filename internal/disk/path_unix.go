//go:build !windows

package disk

import "os"

func isLinkOrReparse(_ string, info os.FileInfo) (bool, error) {
	return info.Mode()&os.ModeSymlink != 0, nil
}
