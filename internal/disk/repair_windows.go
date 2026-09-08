//go:build windows

package disk

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/coalaura/outboxd/internal/windowsacl"
	"golang.org/x/sys/windows"
)

// RepairPrivateTree applies a protected private DACL to every regular object
// beneath root after rejecting reparses and other unsupported objects.
func RepairPrivateTree(root string) error {
	err := ValidatePath(root)
	if err != nil {
		return err
	}

	dir, err := OpenDirectory(root)
	if err != nil {
		return err
	}

	err = inspectWindowsRepairTree(dir)
	closeErr := dir.Close()

	if err != nil {
		return err
	}

	if closeErr != nil {
		return closeErr
	}

	return repairWindowsTree(root)
}

func inspectWindowsRepairTree(dir *os.File) error {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		path := filepath.Join(dir.Name(), entry.Name())

		if entry.Type()&os.ModeSymlink != 0 || entry.Type()&os.ModeIrregular != 0 {
			return fmt.Errorf("private data object %q must not be a reparse point", path)
		}

		if entry.IsDir() {
			child, err := OpenDirectoryAt(dir, entry.Name())
			if err != nil {
				return err
			}

			err = inspectWindowsRepairTree(child)
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
			return fmt.Errorf("private data object %q must be a regular file or directory: %w", path, err)
		}

		err = file.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func repairWindowsTree(root string) error {
	dir, err := openWindowsRepairObject(root, true)
	if err != nil {
		return err
	}

	defer dir.Close()

	return repairWindowsDirectory(dir)
}

func repairWindowsDirectory(dir *os.File) error {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		child, err := openWindowsRepairAt(dir, entry.Name(), entry.IsDir())
		if err != nil {
			return err
		}

		if entry.IsDir() {
			err = repairWindowsDirectory(child)
			if err != nil {
				child.Close()

				return err
			}
		}

		err = windowsacl.RepairHandle(windows.Handle(child.Fd()), entry.IsDir())
		closeErr := child.Close()

		if err != nil {
			return err
		}

		if closeErr != nil {
			return closeErr
		}
	}

	return windowsacl.RepairHandle(windows.Handle(dir.Fd()), true)
}

func openWindowsRepairObject(path string, directory bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)

	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}

	access := uint32(windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.WRITE_DAC | windows.SYNCHRONIZE)

	handle, err := windows.CreateFile(
		name,
		access|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)

	if err != nil {
		handle, err = windows.CreateFile(
			name,
			access,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil,
			windows.OPEN_EXISTING,
			flags,
			0,
		)
	}

	if err != nil {
		return nil, err
	}

	err = rejectReparse(handle, path)
	if err != nil {
		windows.CloseHandle(handle)

		return nil, err
	}

	return os.NewFile(uintptr(handle), path), nil
}

func openWindowsRepairAt(parent *os.File, name string, directory bool) (*os.File, error) {
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.WRITE_DAC | windows.SYNCHRONIZE)
	kind := uint32(windows.FILE_NON_DIRECTORY_FILE | windows.FILE_OPEN_REPARSE_POINT)

	if directory {
		access |= windows.FILE_LIST_DIRECTORY
		kind = windows.FILE_DIRECTORY_FILE | windows.FILE_OPEN_FOR_BACKUP_INTENT
	}

	handle, err := openAt(windows.Handle(parent.Fd()), name, access|windows.WRITE_OWNER, kind)
	if err != nil {
		handle, err = openAt(windows.Handle(parent.Fd()), name, access, kind)
	}

	if err != nil {
		return nil, err
	}

	path := filepath.Join(parent.Name(), name)

	err = rejectReparse(handle, path)
	if err != nil {
		windows.CloseHandle(handle)

		return nil, err
	}

	return os.NewFile(uintptr(handle), path), nil
}
