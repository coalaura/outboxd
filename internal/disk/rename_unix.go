//go:build !windows

package disk

import "os"

func rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}
