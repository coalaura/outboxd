//go:build !windows

package disk

import "os"

func EnsurePrivateRoot(path string) error {
	return MkdirDurable(path)
}

func ValidatePrivateDirectory(string) error {
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
