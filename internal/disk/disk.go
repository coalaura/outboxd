package disk

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// Use the largest allocation unit supported by common deployment filesystems.
// This intentionally overestimates usage on typical 4 KiB filesystems so
// quota admission cannot rely on optimistic apparent sizes.
const allocationUnit int64 = 64 << 10

// Hooks provide a narrow fault-injection seam for tests. Production code
// leaves them nil.
type Hooks struct {
	// BeforeRead is called before queue recovery opens a durable file.
	BeforeRead func(path string) error

	// BeforeRemoveAll is called immediately before recursively removing a path.
	BeforeRemoveAll func(path string) error

	// BeforeSyncFile is called immediately before syncing an open file.
	BeforeSyncFile func(path string) error

	// AfterSyncFile is called after a successful file sync.
	AfterSyncFile func(path string) error

	// AfterClose is called after a successful file.Close before rename.
	AfterClose func(path string) error

	// AfterRename is called after a successful rename.
	AfterRename func(oldpath, newpath string) error

	// AfterSyncDir is called after a successful directory Sync.
	AfterSyncDir func(path string) error

	// BeforeSyncDir is called immediately before syncing a directory.
	BeforeSyncDir func(path string) error

	// BeforeRename is called just before rename.
	BeforeRename func(oldpath, newpath string) error
}

var (
	hookMu sync.RWMutex
	hooks  Hooks
)

// AllocationSize returns a conservative application admission estimate for
// one filesystem object. It is not a measurement of physical disk usage.
// Directory entries and empty files still cost one allocation unit; sparse
// and compressed files are charged by apparent size.
func AllocationSize(size int64) int64 {
	if size <= 0 {
		return allocationUnit
	}

	if size > math.MaxInt64-(allocationUnit-1) {
		return math.MaxInt64
	}

	return ((size + allocationUnit - 1) / allocationUnit) * allocationUnit
}

// AllocatedBytes returns a conservative application admission estimate below
// root. WalkDir uses Lstat semantics and never follows symbolic links.
func AllocatedBytes(root string) (int64, error) {
	var total int64

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}

		charge := AllocationSize(info.Size())
		if total > math.MaxInt64-charge {
			return errors.New("filesystem usage overflow")
		}

		total += charge

		return nil
	})

	return total, err
}

// CheckRead runs the recovery read fault seam.
func CheckRead(path string) error {
	h := currentHooks()

	if h.BeforeRead != nil {
		return h.BeforeRead(path)
	}

	return nil
}

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

// SyncFile flushes an open file and runs the file-sync fault hook.
func SyncFile(file *os.File) error {
	h := currentHooks()

	if h.BeforeSyncFile != nil {
		err := h.BeforeSyncFile(file.Name())
		if err != nil {
			return err
		}
	}

	err := file.Sync()
	if err != nil {
		return err
	}

	h = currentHooks()

	if h.AfterSyncFile != nil {
		return h.AfterSyncFile(file.Name())
	}

	return nil
}

// Mkdir creates a directory and its parents with owner-only permissions.
func Mkdir(path string) error {
	return os.MkdirAll(path, 0700)
}

// ValidatePath rejects any existing symbolic-link or reparse-point component
// in path. Queue roots are private namespaces, so traversal through either is
// never valid even when the final target is a directory.
func ValidatePath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	for current := filepath.Clean(abs); ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			linked, linkErr := isLinkOrReparse(current, info)
			if linkErr != nil {
				return linkErr
			}

			if linked {
				allowed, allowErr := allowNamespaceLink(current)
				if allowErr != nil {
					return allowErr
				}

				if allowed {
					continue
				}

				return &os.PathError{Op: "validate spool namespace", Path: current, Err: errors.New("symbolic link or reparse point is not allowed")}
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}

	return nil
}

// MkdirDurable creates each missing directory component and syncs its parent.
func MkdirDurable(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	missing := make([]string, 0, 4)

	for current := abs; ; current = filepath.Dir(current) {
		info, statErr := os.Stat(current)
		if statErr == nil {
			if !info.IsDir() {
				return &os.PathError{Op: "mkdir", Path: current, Err: os.ErrExist}
			}

			break
		}

		if !os.IsNotExist(statErr) {
			return statErr
		}

		missing = append(missing, current)

		parent := filepath.Dir(current)
		if parent == current {
			return statErr
		}
	}

	if len(missing) == 0 {
		// Repair a prior attempt that created a component but could not confirm
		// its parent sync. Walk all ancestors because the failed component is
		// not knowable on retry.
		for current := abs; ; current = filepath.Dir(current) {
			parent := filepath.Dir(current)
			if parent == current {
				break
			}

			err = Sync(parent)
			if err != nil {
				return err
			}
		}

		return nil
	}

	for _, path := range slices.Backward(missing) {
		created, err := mkdirDurableComponent(path)
		if err != nil {
			if !os.IsExist(err) {
				return err
			}

			info, statErr := os.Stat(path)
			if statErr != nil {
				return statErr
			}

			if !info.IsDir() {
				return &os.PathError{Op: "mkdir", Path: path, Err: os.ErrExist}
			}
		}

		err = Sync(filepath.Dir(path))
		if err != nil {
			if created {
				_ = os.Remove(path)
			}

			return err
		}
	}

	return nil
}

// RemoveAll recursively removes path without following links, reparses, or
// crossing a mount boundary, through the test fault seam.
func RemoveAll(path string) error {
	h := currentHooks()

	if h.BeforeRemoveAll != nil {
		err := h.BeforeRemoveAll(path)
		if err != nil {
			return err
		}
	}

	return removeAllSecure(path)
}

// Temp creates a temporary file inside the target directory of path.
func Temp(path string) (*os.File, error) {
	directory := filepath.Dir(path)

	err := Mkdir(directory)
	if err != nil {
		return nil, err
	}

	file, err := createPrivateTemp(directory, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return nil, err
	}

	err = protectPrivateFile(file.Name())
	if err != nil {
		file.Close()
		os.Remove(file.Name())

		return nil, err
	}

	return file, nil
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
	_, err := WriteWithTempState(path, body, mode)
	return err
}

// WriteWithTempState atomically replaces path and reports whether its temporary
// file may remain after an error. Callers can use the result for disk accounting.
func WriteWithTempState(path string, body []byte, mode os.FileMode) (bool, error) {
	file, err := Temp(path)
	if err != nil {
		return false, err
	}

	temp := file.Name()

	_, err = file.Write(body)
	if err != nil {
		file.Close()
		os.Remove(temp)

		return pathMayExist(temp), err
	}

	err = Commit(file, path, mode)
	if err != nil {
		return pathMayExist(temp), err
	}

	return false, nil
}

func pathMayExist(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

// WriteExclusive writes path, failing with os.ErrExist if it already exists.
func WriteExclusive(path string, body []byte, mode os.FileMode) error {
	err := Mkdir(filepath.Dir(path))
	if err != nil {
		return err
	}

	file, err := createPrivateFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}

	err = protectPrivateFile(path)
	if err != nil {
		file.Close()
		os.Remove(path)

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

	h := currentHooks()
	if h.AfterSyncFile != nil {
		err = h.AfterSyncFile(path)
		if err != nil {
			file.Close()

			return err
		}
	}

	err = file.Close()
	if err != nil {
		return err
	}

	h = currentHooks()
	if h.AfterClose != nil {
		err = h.AfterClose(path)
		if err != nil {
			return err
		}
	}

	remove = false

	return Sync(filepath.Dir(path))
}

// Rename replaces newpath with oldpath and syncs the parent directory.
func Rename(oldpath, newpath string) error {
	h := currentHooks()

	if h.BeforeRename != nil {
		err := h.BeforeRename(oldpath, newpath)
		if err != nil {
			return err
		}
	}

	err := rename(oldpath, newpath)
	if err != nil {
		return err
	}

	h = currentHooks()

	if h.AfterRename != nil {
		err := h.AfterRename(oldpath, newpath)
		if err != nil {
			return err
		}
	}

	err = Sync(filepath.Dir(newpath))
	if err != nil {
		return err
	}

	// A cross-directory rename is durable only after both the destination entry
	// and the source removal have been persisted.
	if filepath.Dir(oldpath) != filepath.Dir(newpath) {
		err := Sync(filepath.Dir(oldpath))
		if err != nil {
			return err
		}
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

	h := currentHooks()

	if h.AfterSyncFile != nil {
		err = h.AfterSyncFile(temp)
		if err != nil {
			return err
		}
	}

	err = file.Close()
	if err != nil {
		return err
	}

	h = currentHooks()

	if h.AfterClose != nil {
		err = h.AfterClose(temp)
		if err != nil {
			return err
		}
	}

	h = currentHooks()

	if h.BeforeRename != nil {
		err = h.BeforeRename(temp, path)
		if err != nil {
			return err
		}
	}

	err = rename(temp, path)
	if err != nil {
		return err
	}

	h = currentHooks()

	if h.AfterRename != nil {
		err = h.AfterRename(temp, path)
		if err != nil {
			return err
		}
	}

	return Sync(filepath.Dir(path))
}
