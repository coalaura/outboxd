//go:build windows

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/windowsacl"
	"golang.org/x/sys/windows"
)

type windowsFileAttributeTag struct {
	attributes uint32
	reparseTag uint32
}

func CheckFile(path string, private bool) error {
	file, err := openChecked(path, private, false)
	if err != nil {
		return err
	}

	return file.Close()
}

func ReadCheckedFile(path string, private, allowSymlink bool, maximum int64) ([]byte, error) {
	file, err := openChecked(path, private, allowSymlink)
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

func openChecked(path string, private, allowSymlink bool) (*os.File, error) {
	if allowSymlink {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		return validateOpenedFile(path, file, private, false)
	}

	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)

	if err != nil {
		return nil, err
	}

	tag := windowsFileAttributeTag{}

	err = windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag)))
	if err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}

	if tag.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)

		return nil, fmt.Errorf("%q must not be a symlink or reparse point", path)
	}

	return validateOpenedFile(path, os.NewFile(uintptr(handle), path), private, !allowSymlink)
}

func validateOpenedFile(path string, file *os.File, private, managed bool) (*os.File, error) {
	info, err := file.Stat()
	if err != nil {
		file.Close()

		return nil, err
	}

	if !info.Mode().IsRegular() {
		file.Close()

		return nil, fmt.Errorf("%q must open as a regular file", path)
	}

	if private {
		err = windowsacl.ValidateHandle(windows.Handle(file.Fd()), path, managed, false)
		if err != nil {
			file.Close()

			return nil, err
		}
	}

	return file, nil
}

func (cfg Config) CheckGeneratedParents(path string) error {
	data, _ := filepath.Abs(filepath.Clean(cfg.ResolvedDataDir()))

	err := disk.ValidatePath(data)
	if err != nil {
		return err
	}

	parent, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}

	relative, err := filepath.Rel(data, parent)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("generated path escapes data directory")
	}

	dir, err := disk.OpenDirectory(data)
	if err != nil {
		return err
	}

	defer dir.Close()

	err = windowsacl.ValidateHandle(windows.Handle(dir.Fd()), data, true, false)
	if err != nil {
		return err
	}
	if relative == "." {
		return nil
	}

	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		child, openErr := disk.OpenDirectoryAt(dir, component)
		if openErr != nil {
			_, statErr := os.Lstat(filepath.Join(dir.Name(), component))
			if errors.Is(statErr, os.ErrNotExist) {
				return nil
			}

			return openErr
		}

		err = windowsacl.ValidateHandle(windows.Handle(child.Fd()), child.Name(), true, false)
		if err != nil {
			child.Close()

			return err
		}

		dir.Close()

		dir = child
	}

	return nil
}
