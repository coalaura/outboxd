//go:build windows

package disk

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/coalaura/outboxd/internal/windowsacl"
	"golang.org/x/sys/windows"
)

type fileAttributeTag struct {
	attributes uint32
	reparseTag uint32
}

type fileDispositionInfo struct {
	deleteFile byte
}

// OpenDirectory opens a directory handle without following its final reparse.
func OpenDirectory(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, err := windows.CreateFile(
		name,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)

	if err != nil {
		return nil, &os.PathError{Op: "open directory", Path: path, Err: err}
	}

	err = rejectReparse(handle, path)
	if err != nil {
		windows.CloseHandle(handle)

		return nil, err
	}

	return os.NewFile(uintptr(handle), path), nil
}

// OpenDirectoryAt opens one directory component relative to a retained parent.
func OpenDirectoryAt(parent *os.File, name string) (*os.File, error) {
	path := filepath.Join(parent.Name(), name)

	handle, err := openAt(
		windows.Handle(parent.Fd()),
		name,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT,
	)

	if err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(handle), path), nil
}

// OpenRegularAt opens one regular file relative to a retained directory.
func OpenRegularAt(parent *os.File, name string) (*os.File, os.FileInfo, error) {
	handle, err := openAt(
		windows.Handle(parent.Fd()),
		name,
		windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT,
	)

	if err != nil {
		return nil, nil, err
	}

	path := filepath.Join(parent.Name(), name)

	err = rejectReparse(handle, path)
	if err != nil {
		windows.CloseHandle(handle)

		return nil, nil, err
	}

	file := os.NewFile(uintptr(handle), path)

	info, err := file.Stat()
	if err != nil {
		file.Close()

		return nil, nil, err
	}

	if !info.Mode().IsRegular() {
		file.Close()

		return nil, nil, fmt.Errorf("%q is not a regular file", path)
	}

	return file, info, nil
}

func openAt(parent windows.Handle, name string, access, kind uint32) (windows.Handle, error) {
	if name != "" && !validWindowsComponent(name) {
		return 0, &os.PathError{Op: "open", Path: name, Err: os.ErrInvalid}
	}

	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}

	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}

	var (
		handle windows.Handle
		status windows.IO_STATUS_BLOCK
	)

	err = windows.NtCreateFile(
		&handle,
		access,
		&attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, kind|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)

	if err != nil {
		return 0, &os.PathError{Op: "open", Path: name, Err: err}
	}

	return handle, nil
}

func validWindowsComponent(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name
}

func rejectReparse(handle windows.Handle, path string) error {
	tag := fileAttributeTag{}

	err := windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag)))
	if err != nil {
		return err
	}

	if tag.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%q must not be a reparse point", path)
	}

	return nil
}

// ValidatePrivateTree retains each parent while opening and validating children.
func ValidatePrivateTree(root string) error {
	dir, err := OpenDirectory(root)
	if err != nil {
		return err
	}

	defer dir.Close()

	return validateWindowsTree(dir)
}

func validateWindowsTree(dir *os.File) error {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		path := filepath.Join(dir.Name(), entry.Name())

		if entry.Type()&os.ModeSymlink != 0 || entry.Type()&os.ModeIrregular != 0 {
			return fmt.Errorf("private spool object %q must not be a reparse point", path)
		}

		if entry.IsDir() {
			child, err := OpenDirectoryAt(dir, entry.Name())
			if err != nil {
				return err
			}

			err = windowsacl.ValidateHandle(windows.Handle(child.Fd()), path, true, false)
			if err == nil {
				err = validateWindowsTree(child)
			}

			closeErr := child.Close()

			if err != nil {
				return err
			}

			if closeErr != nil {
				return closeErr
			}

			continue
		}

		file, _, err := OpenRegularAt(dir, entry.Name())
		if err != nil {
			return err
		}

		err = windowsacl.ValidateHandle(windows.Handle(file.Fd()), path, true, false)

		closeErr := file.Close()
		if err != nil {
			return err
		}

		if closeErr != nil {
			return closeErr
		}
	}

	return nil
}

func removeAllSecure(path string) error {
	path = filepath.Clean(path)

	parent, err := OpenDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}

	defer parent.Close()

	return removeWindowsChild(parent, filepath.Base(path))
}

func removeWindowsChild(parent *os.File, name string) error {
	path := filepath.Join(parent.Name(), name)

	probeName, nameErr := windows.UTF16PtrFromString(path)
	if nameErr != nil {
		return nameErr
	}

	probe, probeErr := windows.CreateFile(
		probeName,
		windows.DELETE|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)

	if probeErr == nil {
		tagErr := rejectReparse(probe, path)
		if tagErr != nil && containsReparseError(tagErr) {
			disposition := fileDispositionInfo{deleteFile: 1}

			err := windows.SetFileInformationByHandle(probe, windows.FileDispositionInfo, (*byte)(unsafe.Pointer(&disposition)), uint32(unsafe.Sizeof(disposition)))

			windows.CloseHandle(probe)

			return err
		}

		windows.CloseHandle(probe)
	}

	handle, err := openAt(
		windows.Handle(parent.Fd()),
		name,
		windows.DELETE|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_OPEN_FOR_BACKUP_INTENT,
	)

	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}

	if err != nil {
		return err
	}

	tagErr := rejectReparse(handle, path)
	if tagErr == nil {
		file := os.NewFile(uintptr(handle), path)

		info, statErr := file.Stat()
		if statErr == nil && info.IsDir() {
			entries, readErr := file.ReadDir(-1)
			if readErr != nil {
				file.Close()

				return readErr
			}

			for _, entry := range entries {
				err = removeWindowsChild(file, entry.Name())
				if err != nil {
					file.Close()

					return err
				}
			}
		}

		if statErr != nil {
			file.Close()

			return statErr
		}

		disposition := fileDispositionInfo{deleteFile: 1}

		err = windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, (*byte)(unsafe.Pointer(&disposition)), uint32(unsafe.Sizeof(disposition)))

		closeErr := file.Close()

		return errors.Join(err, closeErr)
	}

	if tagErr != nil && !containsReparseError(tagErr) {
		windows.CloseHandle(handle)

		return tagErr
	}

	info := fileDispositionInfo{deleteFile: 1}

	err = windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))

	windows.CloseHandle(handle)

	return err
}

func containsReparseError(err error) bool {
	return err != nil && len(err.Error()) >= len("reparse point") && err.Error()[len(err.Error())-len("reparse point"):] == "reparse point"
}

// DuplicateDirectory reopens the directory with an independent enumeration offset.
func DuplicateDirectory(dir *os.File) (*os.File, error) {
	handle, err := openAt(
		windows.Handle(dir.Fd()),
		"",
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_FOR_BACKUP_INTENT,
	)

	if err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(handle), dir.Name()), nil
}
