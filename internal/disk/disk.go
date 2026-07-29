package disk

import (
	"os"
	"path/filepath"
)

// Mkdir creates a directory and its parents with owner-only permissions.
func Mkdir(path string) error {
	return os.MkdirAll(path, 0700)
}

// Temp creates a temporary file inside the target directory of path.
func Temp(path string) (*os.File, error) {
	directory := filepath.Dir(path)

	err := Mkdir(directory)
	if err != nil {
		return nil, err
	}

	return os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
}

// Commit flushes, closes and atomically moves file into place.
func Commit(file *os.File, path string, mode os.FileMode) error {
	temp := file.Name()

	err := commit(file, temp, path, mode)
	if err != nil {
		file.Close()
		os.Remove(temp)

		return err
	}

	return nil
}

// Write atomically replaces the file at path.
func Write(path string, body []byte, mode os.FileMode) error {
	file, err := Temp(path)
	if err != nil {
		return err
	}

	_, err = file.Write(body)
	if err != nil {
		file.Close()

		os.Remove(file.Name())

		return err
	}

	return Commit(file, path, mode)
}

// WriteExclusive writes path, failing with os.ErrExist if it already exists.
func WriteExclusive(path string, body []byte, mode os.FileMode) error {
	err := Mkdir(filepath.Dir(path))
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}

	remove := true

	defer func() {
		if remove {
			os.Remove(path)
		}
	}()

	_, err = file.Write(body)
	if err != nil {
		file.Close()

		return err
	}

	err = file.Sync()
	if err != nil {
		file.Close()

		return err
	}

	err = file.Close()
	if err != nil {
		return err
	}

	remove = false

	return Sync(filepath.Dir(path))
}

func commit(file *os.File, temp, path string, mode os.FileMode) error {
	err := file.Chmod(mode)
	if err != nil {
		return err
	}

	err = file.Sync()
	if err != nil {
		return err
	}

	err = file.Close()
	if err != nil {
		return err
	}

	err = os.Rename(temp, path)
	if err != nil {
		return err
	}

	return Sync(filepath.Dir(path))
}
