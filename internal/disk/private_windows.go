//go:build windows

package disk

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coalaura/outboxd/internal/windowsacl"
	"golang.org/x/sys/windows"
)

// EnsurePrivateRoot creates a managed root with a protected DACL, or validates
// that an existing root is already protected and private.
func EnsurePrivateRoot(path string) error {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		err := MkdirDurable(path)
		if err != nil {
			return err
		}

		err = windowsacl.Protect(path, true)
		if err != nil {
			_ = os.Remove(path)

			return err
		}
	} else if err != nil {
		return err
	} else {
		err := validatePrivateDirectory(path, false)
		if err != nil {
			return err
		}

		err = windowsacl.Protect(path, true)
		if err != nil {
			return err
		}
	}

	return validatePrivateDirectory(path, true)
}

// ValidatePrivateDirectory verifies a managed directory without changing it.
func ValidatePrivateDirectory(path string) error {
	return validatePrivateDirectory(path, false)
}

func ValidatePrivateDirectoryHandle(dir *os.File) error {
	info, err := dir.Stat()
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("private directory %q is not a directory", dir.Name())
	}

	return windowsacl.ValidateHandle(windows.Handle(dir.Fd()), dir.Name(), true, false)
}

func validatePrivateDirectory(path string, requireProtected bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	linked, err := isLinkOrReparse(path, info)
	if err != nil {
		return err
	}

	if linked {
		return fmt.Errorf("private directory %q must not be a reparse point", path)
	}

	if !info.IsDir() {
		return fmt.Errorf("private directory %q is not a directory", path)
	}

	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}

	defer windows.CloseHandle(handle)

	err = windowsacl.ValidateHandle(handle, path, true, requireProtected)
	if err != nil {
		return fmt.Errorf("private directory: %w", err)
	}

	return nil
}

func protectPrivateFile(path string) error {
	return windowsacl.Protect(path, false)
}

func createPrivateFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	attributes, err := windowsacl.SecurityAttributes(false)
	if err != nil {
		return nil, err
	}

	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	return os.NewFile(uintptr(handle), path), nil
}

func createPrivateTemp(directory, prefix string) (*os.File, error) {
	var last error

	for range 100 {
		var random [8]byte

		_, err := rand.Read(random[:])
		if err != nil {
			return nil, err
		}

		path := filepath.Join(directory, prefix+hex.EncodeToString(random[:]))

		file, err := createPrivateFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			return file, nil
		}

		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}

		last = err
	}

	return nil, fmt.Errorf("create private temporary file: %w", last)
}
