//go:build windows

package disk

import (
	"os"

	"golang.org/x/sys/windows"
)

func isLinkOrReparse(path string, info os.FileInfo) (bool, error) {
	if info.Mode()&os.ModeSymlink != 0 {
		return true, nil
	}

	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}

	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return false, err
	}

	return attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

func allowNamespaceLink(string) (bool, error) {
	return false, nil
}
