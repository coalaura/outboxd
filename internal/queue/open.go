package queue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
)

// OpenOptions controls startup maintenance without changing queue semantics.
type OpenOptions struct {
	DisableStartupPrune bool
}

// Close releases the exclusive spool lock after all active operations finish.
func (q *Queue) Close() error {
	return q.CloseContext(context.Background())
}

// CloseContext starts closing the queue and waits up to ctx's deadline. Once
// started, close is irreversible: new operations are rejected and blocked Next
// calls are woken. A deadline only bounds this wait; it cannot cancel arbitrary
// filesystem calls or open readers. The spool lock remains held until every
// active operation finishes and the close completes in the background.
func (q *Queue) CloseContext(ctx context.Context) error {
	if q == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	q.mu.Lock()
	if !q.closing {
		q.closing = true

		close(q.closeSignal)

		go q.finishClose()
	}

	done := q.closeDone
	q.mu.Unlock()

	select {
	case <-done:
		q.mu.Lock()
		err := q.closeErr
		q.mu.Unlock()

		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (q *Queue) finishClose() {
	q.mu.Lock()

	for q.active > 0 {
		q.closeCond.Wait()
	}

	lock := q.lock
	q.lock = nil

	readyDir := q.readyDir
	deadDir := q.deadDir

	q.readyDir = nil
	q.deadDir = nil

	q.mu.Unlock()

	var err error

	if lock != nil {
		err = lock.Close()
	}

	if readyDir != nil {
		err = errors.Join(err, readyDir.Close())
	}

	if deadDir != nil {
		err = errors.Join(err, deadDir.Close())
	}

	q.mu.Lock()
	q.closeErr = err

	close(q.closeDone)
	q.mu.Unlock()
}

// Open loads an existing spool directory, creating it when needed.
// Acquires an exclusive lock on <directory>/.lock before recovery or
// scheduling. Call Close to release it.
// Corrupt entries are relocated to corrupt/ and returned via Queue.Corrupt.
func Open(directory string, limits Limits) (*Queue, error) {
	return OpenWithOptions(directory, limits, OpenOptions{})
}

// OpenForMaintenance opens a writable queue without retention pruning.
func OpenForMaintenance(directory string, limits Limits) (*Queue, error) {
	return OpenWithOptions(directory, limits, OpenOptions{DisableStartupPrune: true})
}

// OpenWithOptions opens a writable queue with explicit startup behavior.
func OpenWithOptions(directory string, limits Limits, options OpenOptions) (*Queue, error) {
	if limits.MaxMessages < 0 || limits.MaxBytes < 0 || limits.MaxMessagesPerUser < 0 || limits.MaxBytesPerUser < 0 || limits.MaxSpoolBytes < 0 || limits.SpoolEmergencyBytes < 0 || limits.MinFreeDisk < 0 || limits.DeadRetention < 0 || limits.CorruptRetention < 0 {
		return nil, errors.New("queue limits must not be negative")
	}

	if limits.MaxSpoolBytes > 0 && (limits.SpoolEmergencyBytes < MinimumSpoolEmergencyBytes || limits.SpoolEmergencyBytes >= limits.MaxSpoolBytes) {
		return nil, fmt.Errorf("spool emergency reserve must be at least %d bytes and smaller than max spool bytes", MinimumSpoolEmergencyBytes)
	}

	q := &Queue{
		root:          directory,
		ready:         filepath.Join(directory, dirReady),
		dead:          filepath.Join(directory, dirDead),
		tmp:           filepath.Join(directory, dirTmp),
		dsn:           filepath.Join(directory, dirDSN),
		corr:          filepath.Join(directory, dirCorrupt),
		trash:         filepath.Join(directory, dirTrash),
		limits:        limits,
		notify:        make(chan struct{}, 1),
		closeSignal:   make(chan struct{}),
		accounted:     make(map[string]accountedEntry),
		scheduled:     make(map[string]*Envelope),
		transitioning: make(map[string]struct{}),
		requeues:      make(map[string][]*Envelope),
		blocked:       make(map[string]struct{}),
		users:         make(map[string]userUsage),
		closeDone:     make(chan struct{}),
	}

	q.closeCond = sync.NewCond(&q.mu)

	if limits.MinFreeDisk > 0 {
		q.FreeDisk = disk.FreeBytes
	}

	err := disk.ValidatePath(q.root)
	if err != nil {
		return nil, err
	}

	err = disk.EnsurePrivateRoot(q.root)
	if err != nil {
		return nil, err
	}

	err = disk.ValidatePrivateDirectory(q.root)
	if err != nil {
		return nil, err
	}

	lock, err := disk.Lock(filepath.Join(q.root, ".lock"))
	if err != nil {
		if errors.Is(err, disk.ErrLocked) {
			return nil, fmt.Errorf("spool %s: %w: another outboxd process holds the queue lock", directory, disk.ErrLocked)
		}

		return nil, err
	}

	q.lock = lock

	err = disk.ValidatePrivateTree(q.root)
	if err != nil {
		_ = q.Close()

		return nil, err
	}

	for _, d := range []string{q.ready, q.dead, q.tmp, q.dsn, q.corr, q.trash} {
		err = disk.MkdirDurable(d)
		if err != nil {
			_ = q.Close()
			return nil, err
		}

		err = disk.ValidatePath(d)
		if err != nil {
			_ = q.Close()
			return nil, err
		}

		err = disk.ValidatePrivateDirectory(d)
		if err != nil {
			_ = q.Close()

			return nil, err
		}
	}

	err = q.refreshSpoolUsage()
	if err != nil {
		_ = q.Close()

		return nil, err
	}

	err = q.recoverTmp()
	if err != nil {
		_ = q.Close()

		return nil, err
	}

	err = q.cleanTrash()
	if err != nil {
		q.Warnings = append(q.Warnings, fmt.Errorf("trash cleanup: %w", err))
	}

	err = q.recoverDSN()
	if err != nil {
		_ = q.Close()

		return nil, err
	}

	q.validateDead()

	err = q.loadReady()
	if err != nil {
		_ = q.Close()

		return nil, err
	}

	if !options.DisableStartupPrune && (limits.DeadRetention > 0 || limits.CorruptRetention > 0) {
		dead, corrupt, pruneErr := q.Prune(time.Now())
		if pruneErr != nil {
			q.Warnings = append(q.Warnings, fmt.Errorf("startup prune: %w", pruneErr))
		} else if dead+corrupt > 0 {
			q.Warnings = append(q.Warnings, fmt.Errorf("startup prune removed %d dead and %d corrupt entries", dead, corrupt))
		}
	}

	err = q.refreshSpoolUsage()
	if err != nil {
		_ = q.Close()

		return nil, err
	}

	return q, nil
}

// OpenReadOnly opens a spool for inspection without taking the exclusive lock
// and without tmp recovery, trash cleanup, or schedule load.
// Supported: ReadyIDs, LoadReady, ExportReady, DeadIDs, LoadDead, ExportDead,
// ReadBody, Path, DeadDir.
// Mutating methods return ErrReadOnly.
func OpenReadOnly(directory string) (*Queue, error) {
	err := disk.ValidatePath(directory)
	if err != nil {
		return nil, err
	}

	err = disk.ValidatePrivateDirectory(directory)
	if err != nil {
		return nil, err
	}

	rootDir, err := disk.OpenDirectory(directory)
	if err != nil {
		return nil, err
	}

	defer rootDir.Close()

	err = disk.ValidatePrivateDirectoryHandle(rootDir)
	if err != nil {
		return nil, err
	}

	dead := filepath.Join(directory, dirDead)
	ready := filepath.Join(directory, dirReady)

	var handles [2]*os.File

	for i, namespace := range []string{ready, dead} {
		handles[i], err = disk.OpenDirectoryAt(rootDir, filepath.Base(namespace))
		if err != nil {
			_, statErr := os.Lstat(namespace)
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
		}

		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			info, linkErr := os.Lstat(namespace)
			if linkErr == nil && info.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("validate spool namespace %s: symbolic link or reparse point is not allowed", namespace)
			}

			for _, handle := range handles {
				if handle != nil {
					handle.Close()
				}
			}

			return nil, err
		}

		err = disk.ValidatePrivateDirectoryHandle(handles[i])
		if err != nil {
			for _, handle := range handles {
				if handle != nil {
					handle.Close()
				}
			}

			return nil, err
		}
	}

	q := &Queue{
		root:          directory,
		ready:         ready,
		dead:          dead,
		tmp:           filepath.Join(directory, dirTmp),
		dsn:           filepath.Join(directory, dirDSN),
		corr:          filepath.Join(directory, dirCorrupt),
		trash:         filepath.Join(directory, dirTrash),
		notify:        make(chan struct{}, 1),
		closeSignal:   make(chan struct{}),
		accounted:     make(map[string]accountedEntry),
		scheduled:     make(map[string]*Envelope),
		transitioning: make(map[string]struct{}),
		requeues:      make(map[string][]*Envelope),
		blocked:       make(map[string]struct{}),
		users:         make(map[string]userUsage),
		closeDone:     make(chan struct{}),
		readOnly:      true,
		readyDir:      handles[0],
		deadDir:       handles[1],
	}

	q.closeCond = sync.NewCond(&q.mu)

	return q, nil
}

// OpenDefault is Open with unlimited quotas.
func OpenDefault(directory string) (*Queue, error) {
	return Open(directory, Limits{})
}
