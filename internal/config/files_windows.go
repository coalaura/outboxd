//go:build windows

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CheckFile verifies file type on Windows. ACL validation is intentionally not
// claimed here; production operators must restrict DACLs on private files.
func CheckFile(path string, private bool) error {
	file, err := openChecked(path, false)
	if err != nil {
		return err
	}
	return file.Close()
}

// ReadCheckedFile validates the opened final handle before reading it. Windows
// mode bits do not represent DACLs; deployments must restrict private-file ACLs.
func ReadCheckedFile(path string, private, allowSymlink bool, maximum int64) ([]byte, error) {
	file, err := openChecked(path, allowSymlink)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		return nil, fmt.Errorf("%q exceeds %d-byte read limit", path, maximum)
	}
	return body, nil
}

func openChecked(path string, allowSymlink bool) (*os.File, error) {
	if allowSymlink {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return validateOpenedFile(path, file)
	}

	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	tag := struct {
		attributes uint32
		reparseTag uint32
	}{}
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	if tag.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("%q must not be a symlink or reparse point", path)
	}
	return validateOpenedFile(path, os.NewFile(uintptr(handle), path))
}

func validateOpenedFile(path string, file *os.File) (*os.File, error) {
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%q must open as a regular file", path)
	}
	return file, nil
}

func (cfg Config) CheckGeneratedParents(path string) error {
	data, _ := filepath.Abs(filepath.Clean(cfg.ResolvedDataDir()))
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("generated path parent %q is a symlink", current)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if current == data {
			return nil
		}
		next := filepath.Dir(current)
		if next == current {
			return fmt.Errorf("generated path escapes data directory")
		}
	}
}
