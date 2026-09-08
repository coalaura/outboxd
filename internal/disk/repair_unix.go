//go:build !windows

package disk

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type privateOwner struct {
	uid int
	gid int
}

// RepairPrivateTree gives every regular object beneath root the root's owner
// and owner-only permissions. Structural validation completes before mutation.
func RepairPrivateTree(root string) error {
	err := ValidatePath(root)
	if err != nil {
		return err
	}

	dir, err := OpenDirectory(root)
	if err != nil {
		return err
	}

	defer dir.Close()

	mount, err := directoryMount(dir)
	if err != nil {
		return err
	}

	owner, err := directoryOwner(dir)
	if err != nil {
		return err
	}

	err = inspectRepairTree(dir, mount)
	if err != nil {
		return err
	}

	return repairDirectoryTree(dir, mount, owner)
}

func directoryOwner(dir *os.File) (privateOwner, error) {
	info, err := dir.Stat()
	if err != nil {
		return privateOwner{}, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return privateOwner{}, fmt.Errorf("cannot determine owner of %q", dir.Name())
	}

	return privateOwner{uid: int(stat.Uid), gid: int(stat.Gid)}, nil
}

func inspectRepairTree(dir *os.File, mount mountIdentity) error {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		path := filepath.Join(dir.Name(), entry.Name())

		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("private data object %q must not be a symbolic link", path)
		}

		if entry.IsDir() {
			child, err := OpenDirectoryAt(dir, entry.Name())
			if err != nil {
				return err
			}

			childMount, inspectErr := directoryMount(child)
			if inspectErr == nil && childMount != mount {
				inspectErr = fmt.Errorf("private data directory %q crosses a mount boundary", child.Name())
			}

			if inspectErr == nil {
				inspectErr = inspectRepairTree(child, mount)
			}

			closeErr := child.Close()

			if inspectErr != nil {
				return inspectErr
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

	_, err = dir.Seek(0, 0)
	return err
}

func repairDirectoryTree(dir *os.File, mount mountIdentity, owner privateOwner) error {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			child, err := OpenDirectoryAt(dir, entry.Name())
			if err != nil {
				return err
			}

			childMount, repairErr := directoryMount(child)
			if repairErr == nil && childMount != mount {
				repairErr = fmt.Errorf("private data directory %q crosses a mount boundary", child.Name())
			}

			if repairErr == nil {
				repairErr = repairDirectoryTree(child, mount, owner)
			}

			closeErr := child.Close()

			if repairErr != nil {
				return repairErr
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

		err = repairPrivateHandle(file, owner, 0600)
		closeErr := file.Close()

		if err != nil {
			return err
		}

		if closeErr != nil {
			return closeErr
		}
	}

	return repairPrivateHandle(dir, owner, 0700)
}

func repairPrivateHandle(file *os.File, owner privateOwner, mode os.FileMode) error {
	err := unix.Fchown(int(file.Fd()), owner.uid, owner.gid)
	if err != nil {
		return err
	}

	return file.Chmod(mode)
}
