//go:build windows

package disk

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func mkdirDurableComponent(path string) (bool, error) {
	temp, err := os.MkdirTemp(filepath.Dir(path), ".outboxd-mkdir-*")
	if err != nil {
		return false, err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(temp)
		}
	}()
	oldptr, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return false, err
	}
	newptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	if err := windows.MoveFileEx(oldptr, newptr, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return false, err
	}
	remove = false
	return true, nil
}
