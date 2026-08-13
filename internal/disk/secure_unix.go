//go:build !windows

package disk

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// OpenDirectory opens the named directory without following the final link.
func OpenDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open directory", Path: path, Err: err}
	}

	return os.NewFile(uintptr(fd), path), nil
}

// OpenDirectoryAt opens one directory component relative to a retained parent.
func OpenDirectoryAt(parent *os.File, name string) (*os.File, error) {
	if !validComponent(name) {
		return nil, &os.PathError{Op: "open directory", Path: name, Err: os.ErrInvalid}
	}

	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open directory", Path: name, Err: err}
	}

	return os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name)), nil
}

// OpenRegularAt opens one regular file relative to a retained directory.
func OpenRegularAt(parent *os.File, name string) (*os.File, os.FileInfo, error) {
	if !validComponent(name) {
		return nil, nil, &os.PathError{Op: "open", Path: name, Err: os.ErrInvalid}
	}

	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: name, Err: err}
	}

	file := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))

	info, err := file.Stat()
	if err != nil {
		file.Close()

		return nil, nil, err
	}

	if !info.Mode().IsRegular() {
		file.Close()

		return nil, nil, fmt.Errorf("%q is not a regular file", file.Name())
	}

	return file, info, nil
}

func validComponent(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name
}

// DuplicateDirectory reopens the directory with an independent enumeration offset.
func DuplicateDirectory(dir *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(fd), dir.Name()), nil
}

func ValidatePrivateTree(root string) error {
	dir, err := OpenDirectory(root)
	if err != nil {
		return err
	}

	defer dir.Close()

	mount, err := directoryMount(dir)
	if err != nil {
		return err
	}

	return validateDirectoryTree(dir, mount)
}

func validateDirectoryTree(dir *os.File, mount mountIdentity) error {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("private spool object %q must not be a symbolic link", filepath.Join(dir.Name(), entry.Name()))
		}

		if !entry.IsDir() {
			continue
		}

		child, err := OpenDirectoryAt(dir, entry.Name())
		if err != nil {
			return err
		}

		childMount, mountErr := directoryMount(child)
		if mountErr == nil && childMount != mount {
			mountErr = fmt.Errorf("private spool directory %q crosses a mount boundary", child.Name())
		}

		if mountErr == nil {
			mountErr = validateDirectoryTree(child, mount)
		}

		closeErr := child.Close()

		if mountErr != nil {
			return mountErr
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

	name := filepath.Base(path)

	var st unix.Stat_t

	err = unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}

	if err != nil {
		return err
	}

	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(int(parent.Fd()), name, 0)
	}

	dir, err := OpenDirectoryAt(parent, name)
	if err != nil {
		return err
	}

	parentMount, err := directoryMount(parent)
	if err != nil {
		dir.Close()

		return err
	}

	mount, err := directoryMount(dir)
	if err == nil && mount != parentMount {
		err = fmt.Errorf("refusing to remove %q across a mount boundary", dir.Name())
	}

	if err == nil {
		err = removeDirectoryContents(dir, mount)
	}

	closeErr := dir.Close()

	if err != nil {
		return err
	}

	if closeErr != nil {
		return closeErr
	}

	return unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
}

func removeDirectoryContents(dir *os.File, mount mountIdentity) error {
	entries, err := dir.ReadDir(-1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	for _, entry := range entries {
		name := entry.Name()

		var st unix.Stat_t

		err = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			continue
		}

		if err != nil {
			return err
		}

		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			err = unix.Unlinkat(int(dir.Fd()), name, 0)
			if err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}

			continue
		}

		child, err := OpenDirectoryAt(dir, name)
		if err != nil {
			return err
		}

		childMount, mountErr := directoryMount(child)
		if mountErr == nil && childMount != mount {
			mountErr = fmt.Errorf("refusing to remove %q across a mount boundary", child.Name())
		}

		if mountErr == nil {
			mountErr = removeDirectoryContents(child, mount)
		}

		closeErr := child.Close()

		if mountErr != nil {
			return mountErr
		}

		if closeErr != nil {
			return closeErr
		}

		err = unix.Unlinkat(int(dir.Fd()), name, unix.AT_REMOVEDIR)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}

	return nil
}
