package disk

import (
	"os"
	"path/filepath"
	"sync"
)

// Hooks provide a narrow fault-injection seam for tests. Production code
// leaves them nil.
type Hooks struct {
	// AfterSyncFile is called after a successful file.Sync during Commit/WriteExclusive.
	AfterSyncFile func(path string) error
	// AfterClose is called after a successful file.Close before rename.
	AfterClose func(path string) error
	// AfterRename is called after a successful rename.
	AfterRename func(oldpath, newpath string) error
	// AfterSyncDir is called after a successful directory Sync.
	AfterSyncDir func(path string) error
	// BeforeRename is called just before rename.
	BeforeRename func(oldpath, newpath string) error
}

var (
	hookMu sync.RWMutex
	hooks  Hooks
)

// SetHooks installs test hooks. Pass a zero Hooks to clear.
func SetHooks(h Hooks) {
	hookMu.Lock()
	hooks = h
	hookMu.Unlock()
}

func currentHooks() Hooks {
	hookMu.RLock()
	defer hookMu.RUnlock()
	return hooks
}

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
	if h := currentHooks(); h.AfterSyncFile != nil {
		if err := h.AfterSyncFile(path); err != nil {
			file.Close()
			return err
		}
	}

	err = file.Close()
	if err != nil {
		return err
	}
	if h := currentHooks(); h.AfterClose != nil {
		if err := h.AfterClose(path); err != nil {
			return err
		}
	}

	remove = false
	return Sync(filepath.Dir(path))
}

// Rename replaces newpath with oldpath and syncs the parent directory.
func Rename(oldpath, newpath string) error {
	if h := currentHooks(); h.BeforeRename != nil {
		if err := h.BeforeRename(oldpath, newpath); err != nil {
			return err
		}
	}
	if err := os.Rename(oldpath, newpath); err != nil {
		return err
	}
	if h := currentHooks(); h.AfterRename != nil {
		if err := h.AfterRename(oldpath, newpath); err != nil {
			return err
		}
	}
	if err := Sync(filepath.Dir(newpath)); err != nil {
		return err
	}
	// Also sync source parent when different.
	if filepath.Dir(oldpath) != filepath.Dir(newpath) {
		_ = Sync(filepath.Dir(oldpath))
	}
	return nil
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
	if h := currentHooks(); h.AfterSyncFile != nil {
		if err := h.AfterSyncFile(temp); err != nil {
			return err
		}
	}

	err = file.Close()
	if err != nil {
		return err
	}
	if h := currentHooks(); h.AfterClose != nil {
		if err := h.AfterClose(temp); err != nil {
			return err
		}
	}

	if h := currentHooks(); h.BeforeRename != nil {
		if err := h.BeforeRename(temp, path); err != nil {
			return err
		}
	}

	err = os.Rename(temp, path)
	if err != nil {
		return err
	}
	if h := currentHooks(); h.AfterRename != nil {
		if err := h.AfterRename(temp, path); err != nil {
			return err
		}
	}

	return Sync(filepath.Dir(path))
}
