// Package queue implements a durable, crash-safe outbound message spool.
//
// # Semantics
//
// Delivery is at-least-once. A process crash between a successful SMTP DATA
// response and Finish can redeliver the same message. Callers must tolerate
// duplicates. The queue never claims exactly-once SMTP delivery.
//
// # On-disk layout
//
// Each queue item is a directory. Same-filesystem directory renames are the
// atomic state transition:
//
//	<root>/
//	  tmp/<id>/          # under construction (not scheduled)
//	  dsn/<id>/          # linked DSN awaiting publication (not scheduled)
//	  ready/<id>/        # durable, eligible for delivery
//	    add.state         # versioned Add acceptance marker
//	    meta.json
//	    message.eml
//	  dead/<id>/         # permanent failure / exhausted
//	  corrupt/<id>/      # quarantined unreadable entries
//
// Queue.Add builds under tmp/ and renames into ready/. Finish moves ready →
// trash rename-delete. Bury moves ready → dead. Corrupt entries are moved to
// corrupt/ with a logged error; they are never silently deleted.
package queue

import (
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
)

// Queue is a durable, crash-safe spool of messages awaiting delivery.
// gost:preserve-layout
type Queue struct {
	root  string
	ready string
	dead  string
	tmp   string
	dsn   string
	corr  string
	trash string

	limits Limits

	// FreeDisk is optional; when set, Add consults it for MinFreeDisk.
	FreeDisk func(path string) (int64, error)

	mu            sync.Mutex
	spoolMu       sync.Mutex
	pending       schedule
	notify        chan struct{}
	closeSignal   chan struct{}
	count         int
	bytes         int64
	accounted     map[string]accountedEntry
	scheduled     map[string]*Envelope
	transitioning map[string]struct{}
	requeues      map[string][]*Envelope
	reserved      int   // in-flight Add reservations (count)
	resBytes      int64 // in-flight Add reservations (bytes)
	users         map[string]userUsage
	spoolBytes    int64 // conservative admission estimate across all namespaces
	spoolReserved int64 // in-flight spool admission reservations
	lastSpoolScan time.Time
	active        int
	closing       bool
	closeDone     chan struct{}
	closeCond     *sync.Cond
	closeErr      error

	// lock is the exclusive process lock on <root>/.lock (nil for read-only).
	lock *disk.FileLock

	// readOnly queues skip recovery/scheduling and reject mutations.
	readOnly bool
	readyDir *os.File
	deadDir  *os.File

	// Corrupt holds reportable quarantine events from Open.
	Corrupt []error

	// Warnings holds nonfatal startup maintenance errors.
	Warnings []error
	blocked  map[string]struct{}

	// afterPublish is a test seam invoked after publication is signaled but
	// before the publishing operation returns.
	afterPublish func()

	// afterBodyOpen is a test seam invoked after the exact body handle has
	// passed its initial size check.
	afterBodyOpen func()

	// afterBodyVerify is a test seam invoked after openBody's validation pass
	// but before ReadBody or ExportDead reads the bytes it will expose.
	afterBodyVerify func()

	// beforeAddRollback is a test seam for an acceptance error whose rollback
	// cannot restore the pending marker.
	beforeAddRollback func() error
}

// Path returns the spool root.
func (q *Queue) Path() string {
	return q.root
}

// DeadDir returns the dead-letter directory.
func (q *Queue) DeadDir() string {
	return q.dead
}

// Len returns the number of messages waiting for delivery.
func (q *Queue) Len() int {
	if q == nil || q.beginOperation() != nil {
		return 0
	}

	defer q.endOperation()

	q.mu.Lock()
	defer q.mu.Unlock()

	return q.pending.Len()
}

// Stats returns durable ready-queue occupancy including in-progress adds.
func (q *Queue) Stats() (messages int, bytes int64) {
	if q == nil || q.beginOperation() != nil {
		return 0, 0
	}

	defer q.endOperation()

	q.mu.Lock()
	defer q.mu.Unlock()

	messages, ok := checkedAddInt(q.count, q.reserved)
	if !ok {
		messages = math.MaxInt
	}

	bytes, ok = checkedAddInt64(q.bytes, q.resBytes)
	if !ok {
		bytes = math.MaxInt64
	}

	return messages, bytes
}

func (q *Queue) startMutation() error {
	q.spoolMu.Lock()

	q.mu.Lock()
	limit := q.limits.MaxSpoolBytes - q.limits.SpoolEmergencyBytes

	used, ok := checkedAddInt64(q.spoolBytes, q.spoolReserved)

	nearLimit := q.limits.MaxSpoolBytes > 0 && (!ok || limit < 0 || used >= limit)

	stale := time.Since(q.lastSpoolScan) >= time.Minute
	q.mu.Unlock()

	if nearLimit && stale {
		err := q.refreshSpoolUsage()
		if err != nil {
			q.spoolMu.Unlock()

			return fmt.Errorf("measure spool usage: %w", err)
		}
	}

	return nil
}

func (q *Queue) finishMutation() {
	q.spoolMu.Unlock()
}

func (q *Queue) refreshSpoolUsage() error {
	total, err := disk.AllocatedBytes(q.root)
	if err != nil {
		return err
	}

	q.mu.Lock()
	q.spoolBytes = total
	q.lastSpoolScan = time.Now()
	q.mu.Unlock()

	return nil
}

func (q *Queue) rejectReadOnly() error {
	if q.readOnly {
		return ErrReadOnly
	}

	return nil
}

func (q *Queue) beginOperation() error {
	if q == nil {
		return ErrQueueClosed
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closing {
		return ErrQueueClosed
	}

	q.active++

	return nil
}

func (q *Queue) endOperation() {
	q.mu.Lock()

	q.active--

	if q.active == 0 && q.closing {
		q.closeCond.Broadcast()
	}

	q.mu.Unlock()
}
