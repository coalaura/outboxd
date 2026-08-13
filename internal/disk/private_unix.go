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
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("private directory %q is not a directory", path)
	}

	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private directory %q permissions %04o allow group or other access", path, info.Mode().Perm())
	}

	return nil
}

func ValidatePrivateTree(string) error {
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
