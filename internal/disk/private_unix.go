//go:build !windows

package disk

import (
	"fmt"
	"os"
)

func EnsurePrivateRoot(path string) error {
	err := ValidatePath(path)
	if err != nil {
		return err
	}

	err = MkdirDurable(path)
	if err != nil {
		return err
	}

	return ValidatePrivateDirectory(path)
}

func ValidatePrivateDirectory(path string) error {
	dir, err := OpenDirectory(path)
	if err != nil {
		return err
	}

	defer dir.Close()

	return ValidatePrivateDirectoryHandle(dir)
}

func ValidatePrivateDirectoryHandle(dir *os.File) error {
	info, err := dir.Stat()
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("private directory %q is not a directory", dir.Name())
	}

	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private directory %q permissions %04o allow group or other access", dir.Name(), info.Mode().Perm())
	}

	return nil
}

func protectPrivateFile(string) error {
	return nil
}

func createPrivateFile(path string, flag int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, mode)
}

func createPrivateTemp(directory, prefix string) (*os.File, error) {
	return os.CreateTemp(directory, prefix+"*")
}
