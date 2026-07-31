package disk

import "errors"

// ErrLocked is returned when another process (or open handle) holds the
// exclusive spool lock.
var ErrLocked = errors.New("resource locked")

// FileLock is an exclusive file lock held for the process lifetime of the open
// file descriptor. Close releases the lock.
type FileLock struct {
	impl fileLockImpl
}

// Close releases the lock and closes the underlying file.
func (l *FileLock) Close() error {
	if l == nil || l.impl == nil {
		return nil
	}
	err := l.impl.close()
	l.impl = nil
	return err
}

// fileLockImpl is the platform-specific lock state.
type fileLockImpl interface {
	close() error
}
