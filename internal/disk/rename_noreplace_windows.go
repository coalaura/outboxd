//go:build windows

package disk

import "golang.org/x/sys/windows"

func renameNoReplace(oldpath, newpath string) error {
	oldptr, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}

	newptr, err := windows.UTF16PtrFromString(newpath)
	if err != nil {
		return err
	}

	return windows.MoveFileEx(oldptr, newptr, windows.MOVEFILE_WRITE_THROUGH)
}
