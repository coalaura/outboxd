//go:build !linux && !darwin && !windows

package disk

import (
	"errors"
)

func renameNoReplace(oldpath, newpath string) error {
	return errors.New("atomic no-replace rename is unsupported on this platform")
}
