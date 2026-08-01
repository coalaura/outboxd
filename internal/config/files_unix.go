//go:build !windows

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// CheckFile rejects symlinks/non-regular files and, for private material,
// group/other permissions. It intentionally does not follow the final path.
func CheckFile(path string, private bool) error {
	file, err := openChecked(path, private, false)
	if err != nil {
		return err
	}

	return file.Close()
}

// ReadCheckedFile reads and validates the same opened file handle. allowSymlink
// is reserved for operator-managed TLS paths; generated secrets must pass false.
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
	flags := unix.O_RDONLY | unix.O_CLOEXEC
	if !allowSymlink {
		flags |= unix.O_NOFOLLOW
	}

	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}

	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%q must open as a regular file", path)
	}

	if private && info.Mode().Perm()&0077 != 0 {
		file.Close()
		return nil, fmt.Errorf("%q permissions %04o allow group or other access", path, info.Mode().Perm())
	}

	return file, nil
}

// CheckGeneratedParents rejects existing symlink parents beneath data_directory.
func (cfg Config) CheckGeneratedParents(path string) error {
	data, _ := filepath.Abs(filepath.Clean(cfg.ResolvedDataDir()))
	parent := filepath.Dir(path)

	for current := parent; ; current = filepath.Dir(current) {
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
