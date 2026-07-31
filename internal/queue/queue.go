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
	"bytes"
	"container/heap"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coalaura/outboxd/internal/disk"
	"github.com/coalaura/outboxd/internal/mailbox"
)

// Status is the delivery state of a single recipient.
type Status string

const (
	StatusPending Status = "pending"
	StatusSent    Status = "sent"
	StatusFailed  Status = "failed"
)

const (
	metaName       = "meta.json"
	bodyName       = "message.eml"
	addStateName   = "add.state"
	reviveMetaName = "revive.json"

	// Equal-length states allow the acceptance transition to update the
	// already-durable marker in place without another directory mutation.
	addPending  = "outboxd-add-v1:pending \n"
	addAccepted = "outboxd-add-v1:accepted\n"

	dirReady   = "ready"
	dirDead    = "dead"
	dirTmp     = "tmp"
	dirDSN     = "dsn"
	dirCorrupt = "corrupt"
	dirTrash   = "trash"
)

// idPattern accepts the envelope IDs this process generates and previously
// generated forms. Paths, separators and traversal sequences are rejected.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,190}$`)

// Recipient is one envelope recipient and its delivery outcome.
type Recipient struct {
	Address string `json:"address"`
	Domain  string `json:"domain"`
	Status  Status `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Code    int    `json:"code,omitempty"`
}

// Envelope is the queued metadata for one accepted message.
type Envelope struct {
	ID          string      `json:"id"`
	Incarnation string      `json:"incarnation"`
	Revision    uint64      `json:"revision"`
	Username    string      `json:"username"`
	Sender      string      `json:"sender"`
	Recipients  []Recipient `json:"recipients"`
	Size        int64       `json:"size"`
	Created     time.Time   `json:"created"`
	Attempts    int         `json:"attempts"`
	NextAttempt time.Time   `json:"next_attempt"`
	LastError   string      `json:"last_error,omitempty"`
	SMTPUTF8    bool        `json:"smtp_utf8,omitempty"`
	EightBit    bool        `json:"eight_bit,omitempty"`
	// DSNID links a source to the exact DSN durably created for this generation.
	DSNID string `json:"dsn_id,omitempty"`
	// DSNSourceID is set on generated DSNs, preventing recursive notifications
	// and allowing recovery to verify the reciprocal source identity.
	DSNSourceID          string `json:"dsn_source_id,omitempty"`
	DSNSourceIncarnation string `json:"dsn_source_incarnation,omitempty"`
	DSNGeneration        uint64 `json:"dsn_generation,omitempty"`
	// EnqueuedAt is used by quota accounting for in-progress adds.
	EnqueuedAt time.Time `json:"-"`

	index int
}

// Limits caps the durable queue. Zero means unlimited for that dimension.
type Limits struct {
	MaxMessages int
	MaxBytes    int64
	MinFreeDisk int64
}

type accountedEntry struct {
	size        int64
	incarnation string
	revision    uint64
}

// Queue is a durable, crash-safe spool of messages awaiting delivery.
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
	pending       schedule
	notify        chan struct{}
	count         int
	bytes         int64
	accounted     map[string]accountedEntry
	scheduled     map[string]struct{}
	transitioning map[string]struct{}
	requeues      map[string][]*Envelope
	reserved      int   // in-flight Add reservations (count)
	resBytes      int64 // in-flight Add reservations (bytes)

	// lock is the exclusive process lock on <root>/.lock (nil for read-only).
	lock *disk.FileLock
	// readOnly queues skip recovery/scheduling and reject mutations.
	readOnly bool

	// Corrupt holds reportable quarantine events from Open.
	Corrupt []error
	// Warnings holds nonfatal startup maintenance errors.
	Warnings []error

	// afterPublish is a test seam invoked after publication is signaled but
	// before the publishing operation returns.
	afterPublish func()
}

// Pending reports how many recipients still need a delivery attempt.
func (e *Envelope) Pending() int {
	var count int
	for i := range e.Recipients {
		if e.Recipients[i].Status == StatusPending {
			count++
		}
	}
	return count
}

// Failed reports how many recipients permanently failed.
func (e *Envelope) Failed() int {
	var count int
	for i := range e.Recipients {
		if e.Recipients[i].Status == StatusFailed {
			count++
		}
	}
	return count
}

// Len returns the number of messages waiting for delivery.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pending.Len()
}

// Stats returns durable ready-queue occupancy including in-progress adds.
func (q *Queue) Stats() (messages int, bytes int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.count + q.reserved, q.bytes + q.resBytes
}

// Reserve holds capacity for an in-progress Add so concurrent submissions
// cannot overshoot quotas. Release with ReleaseReserve if Add is abandoned.
func (q *Queue) Reserve(size int64) error {
	if err := q.rejectReadOnly(); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.reserveLocked(size, false)
}

// reserveLocked checks quotas. When exempt is true, MaxMessages and MaxBytes are
// skipped so a terminal notification can be staged while its source still
// occupies the queue. MinFreeDisk still applies to every write.
func (q *Queue) reserveLocked(size int64, exempt bool) error {
	if !exempt {
		if q.limits.MaxMessages > 0 && q.count+q.reserved+1 > q.limits.MaxMessages {
			return ErrQueueFull
		}
		if q.limits.MaxBytes > 0 && q.bytes+q.resBytes+size > q.limits.MaxBytes {
			return ErrQueueFull
		}
	}
	if q.limits.MinFreeDisk > 0 && q.FreeDisk != nil {
		free, err := q.FreeDisk(q.root)
		if err != nil {
			return err
		}
		if free < q.limits.MinFreeDisk+size {
			return ErrInsufficientDisk
		}
	}
	q.reserved++
	q.resBytes += size
	return nil
}

// ReleaseReserve undoes Reserve.
func (q *Queue) ReleaseReserve(size int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.releaseReserveLocked(size)
}

func (q *Queue) releaseReserveLocked(size int64) {
	if q.reserved > 0 {
		q.reserved--
	}
	q.resBytes -= size
	if q.resBytes < 0 {
		q.resBytes = 0
	}
}

var (
	// ErrQueueFull is returned when message count or byte quotas are exhausted.
	ErrQueueFull = errors.New("queue full")
	// ErrInsufficientDisk is returned when free disk is below the threshold.
	ErrInsufficientDisk = errors.New("insufficient free disk space")
	// ErrInvalidID is returned for unusable queue identifiers.
	ErrInvalidID = errors.New("invalid queue id")
	// ErrReadOnly is returned when a mutating method is called on a read-only queue.
	ErrReadOnly = errors.New("queue opened read-only")
	// ErrQueueBusy is returned when another operation owns the same queue ID.
	ErrQueueBusy = errors.New("queue id is busy")
	// ErrIDConflict is returned when an ID names a different durable queue item.
	ErrIDConflict = errors.New("queue id conflict")
	// ErrCleanup reports that terminal state committed but garbage cleanup did not.
	ErrCleanup = errors.New("queue cleanup incomplete")
)

func (q *Queue) rejectReadOnly() error {
	if q.readOnly {
		return ErrReadOnly
	}
	return nil
}

// ValidateID rejects path traversal and malformed identifiers.
func ValidateID(id string) error {
	if id == "" || !idPattern.MatchString(id) {
		return ErrInvalidID
	}
	if id == "." || id == ".." || strings.ContainsAny(id, `/\`) {
		return ErrInvalidID
	}
	if filepath.Base(id) != id || filepath.IsAbs(id) {
		return ErrInvalidID
	}
	clean := filepath.Clean(id)
	if clean != id {
		return ErrInvalidID
	}
	return nil
}

// DSNID returns the stable queue ID for one source-message incarnation and
// notification generation.
func DSNID(sourceID, incarnation string, generation uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("outboxd-dsn-v1\x00%s\x00%s\x00%d", sourceID, incarnation, generation)))
	return fmt.Sprintf("dsn.%x", sum)
}

func newIncarnation() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

// Add durably stores a message and schedules it for immediate delivery.
// The accepted marker is the commit point: before it is synced, neither tmp/
// nor a pending ready/ entry is recoverable as an accepted message.
func (q *Queue) Add(envelope *Envelope, data []byte) error {
	if err := q.rejectReadOnly(); err != nil {
		return err
	}
	if err := ValidateID(envelope.ID); err != nil {
		return err
	}
	if envelope.DSNSourceID != "" || envelope.DSNID != "" || envelope.DSNGeneration != 0 {
		return errors.New("DSN state is managed by AddDSN and ReviveDead")
	}
	incarnation, err := newIncarnation()
	if err != nil {
		return err
	}
	envelope.Incarnation = incarnation
	envelope.Revision = 1
	if err := q.beginTransition(envelope.ID); err != nil {
		return err
	}
	owned := true
	defer func() {
		if owned {
			q.endTransition(envelope.ID)
		}
	}()
	q.mu.Lock()
	_, exists := q.accounted[envelope.ID]
	q.mu.Unlock()
	if exists {
		return fmt.Errorf("%w: queue id %s is already ready", ErrIDConflict, envelope.ID)
	}
	readyDir := filepath.Join(q.ready, envelope.ID)
	if _, err := os.Stat(readyDir); err == nil {
		state, stateErr := os.ReadFile(filepath.Join(readyDir, addStateName))
		if stateErr != nil {
			return stateErr
		}
		if string(state) == addAccepted {
			return fmt.Errorf("%w: queue id %s already exists", ErrIDConflict, envelope.ID)
		}
		if err := q.quarantineDir(readyDir, envelope.ID+"-uncommitted"); err != nil {
			return fmt.Errorf("reconcile prior uncommitted add: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, dir := range []string{q.dead, q.dsn} {
		if _, err := os.Stat(filepath.Join(dir, envelope.ID)); err == nil {
			return fmt.Errorf("%w: queue id %s already exists", ErrIDConflict, envelope.ID)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	envelope.Size = int64(len(data))
	if err := validateEnvelope(envelope); err != nil {
		return err
	}

	// Capacity check accounts for concurrent in-progress connections via reserved.
	q.mu.Lock()
	if err := q.reserveLocked(envelope.Size, false); err != nil {
		q.mu.Unlock()
		return err
	}
	q.mu.Unlock()

	held := true
	defer func() {
		if held {
			q.ReleaseReserve(envelope.Size)
		}
	}()

	tmpDir := filepath.Join(q.tmp, envelope.ID)
	if err := os.RemoveAll(tmpDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := disk.Mkdir(tmpDir); err != nil {
		return err
	}

	// Cleanup tmp on any failure after creation.
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(tmpDir)
			_ = disk.Sync(q.tmp)
		}
	}()

	statePath := filepath.Join(tmpDir, addStateName)
	if err := disk.Write(statePath, []byte(addPending), 0600); err != nil {
		return err
	}

	bodyPath := filepath.Join(tmpDir, bodyName)
	if err := disk.Write(bodyPath, data, 0600); err != nil {
		return err
	}

	meta, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	metaPath := filepath.Join(tmpDir, metaName)
	if err := disk.Write(metaPath, meta, 0600); err != nil {
		return err
	}

	if err := disk.Sync(tmpDir); err != nil {
		return err
	}

	if err := disk.Rename(tmpDir, readyDir); err != nil {
		return err
	}
	if err := acceptAdd(filepath.Join(readyDir, addStateName)); err != nil {
		if abortErr := q.quarantineDir(readyDir, envelope.ID+"-uncommitted"); abortErr == nil {
			return err
		} else {
			// If quarantine itself fails while an accepted marker is visible,
			// report success rather than invite a duplicate retry for an entry
			// that recovery will deliver.
			state, readErr := os.ReadFile(filepath.Join(readyDir, addStateName))
			if readErr != nil || string(state) != addAccepted {
				return errors.Join(err, fmt.Errorf("quarantine failed add: %w", abortErr), readErr)
			}
		}
	}

	success = true
	held = false

	q.mu.Lock()
	q.releaseReserveLocked(envelope.Size)
	q.noteAddedLocked(envelope)
	delete(q.transitioning, envelope.ID)
	delete(q.requeues, envelope.ID)
	q.scheduleLocked(envelope)
	q.mu.Unlock()
	owned = false

	q.signal()
	if q.afterPublish != nil {
		q.afterPublish()
	}
	return nil
}

// AddDSN durably links a generated DSN to its source before making the DSN
// schedulable. Recovery completes a linked stage after a crash.
func (q *Queue) AddDSN(source, dsn *Envelope, data []byte) error {
	if err := q.rejectReadOnly(); err != nil {
		return err
	}
	if source == nil || dsn == nil {
		return errors.New("missing DSN envelope")
	}
	if err := ValidateID(source.ID); err != nil {
		return err
	}
	if dsn.DSNSourceID != source.ID || dsn.DSNSourceIncarnation != source.Incarnation || dsn.DSNGeneration != source.DSNGeneration || dsn.ID != DSNID(source.ID, source.Incarnation, source.DSNGeneration) {
		return fmt.Errorf("%w: DSN identity mismatch", ErrIDConflict)
	}
	if source.DSNSourceID != "" {
		return errors.New("cannot generate a DSN for a DSN")
	}
	if dsn.Incarnation == "" {
		incarnation, err := newIncarnation()
		if err != nil {
			return err
		}
		dsn.Incarnation = incarnation
	}
	dsn.Revision = 1
	dsn.Size = int64(len(data))
	if err := validateEnvelope(dsn); err != nil {
		return err
	}
	if err := q.beginTransitions(source.ID, dsn.ID); err != nil {
		return err
	}
	owned := true
	defer func() {
		if owned {
			q.endTransitions(source.ID, dsn.ID)
		}
	}()

	sourceDir := filepath.Join(q.ready, source.ID)
	durableSource, err := q.loadDir(sourceDir, source.ID)
	if err != nil {
		return err
	}
	if durableSource.DSNGeneration != source.DSNGeneration {
		return fmt.Errorf("%w: source DSN generation changed", ErrIDConflict)
	}
	if durableSource.Incarnation != source.Incarnation {
		return fmt.Errorf("%w: source incarnation changed", ErrIDConflict)
	}
	if durableSource.DSNID != "" {
		if durableSource.DSNID != dsn.ID {
			return fmt.Errorf("%w: source links %s", ErrIDConflict, durableSource.DSNID)
		}
		staged, published, publishErr := q.publishStagedDSN(dsn)
		if published {
			q.mu.Lock()
			q.noteAddedLocked(staged)
			delete(q.transitioning, source.ID)
			delete(q.transitioning, dsn.ID)
			delete(q.requeues, source.ID)
			delete(q.requeues, dsn.ID)
			q.scheduleLocked(staged)
			q.mu.Unlock()
			owned = false
			q.signal()
			if q.afterPublish != nil {
				q.afterPublish()
			}
		}
		if publishErr != nil {
			return publishErr
		}
		source.DSNID = dsn.ID
		source.Revision = durableSource.Revision
		return nil
	}
	if durableSource.Revision != source.Revision {
		return fmt.Errorf("%w: source metadata changed", ErrIDConflict)
	}

	for _, dir := range []string{q.ready, q.dead} {
		if _, err := os.Stat(filepath.Join(dir, dsn.ID)); err == nil {
			return fmt.Errorf("%w: %s already exists", ErrIDConflict, dsn.ID)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	stageDir := filepath.Join(q.dsn, dsn.ID)
	if _, err := os.Stat(stageDir); err == nil {
		// The durable source is unlinked, so an existing stage never crossed the
		// protocol commit point and can be replaced by this retry.
		if err := os.RemoveAll(stageDir); err != nil {
			return err
		}
		if err := disk.Sync(q.dsn); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	q.mu.Lock()
	if err := q.reserveLocked(dsn.Size, true); err != nil {
		q.mu.Unlock()
		return err
	}
	q.mu.Unlock()
	held := true
	defer func() {
		if held {
			q.ReleaseReserve(dsn.Size)
		}
	}()

	if err := os.Mkdir(stageDir, 0700); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stageDir)
			_ = disk.Sync(q.dsn)
		}
	}()
	if err := disk.Sync(q.dsn); err != nil {
		return err
	}
	if err := disk.Write(filepath.Join(stageDir, addStateName), []byte(addPending), 0600); err != nil {
		return err
	}
	if err := disk.Write(filepath.Join(stageDir, bodyName), data, 0600); err != nil {
		return err
	}
	meta, err := json.Marshal(dsn)
	if err != nil {
		return err
	}
	if err := disk.Write(filepath.Join(stageDir, metaName), meta, 0600); err != nil {
		return err
	}
	if err := disk.Sync(stageDir); err != nil {
		return err
	}
	if err := acceptAdd(filepath.Join(stageDir, addStateName)); err != nil {
		return err
	}

	linked := *source
	linked.DSNID = dsn.ID
	if err := validateEnvelope(&linked); err != nil {
		return err
	}
	if err := q.storeReady(&linked); err != nil {
		// Preserve the complete stage. Startup decides whether the source update
		// committed and either publishes or quarantines it.
		cleanup = false
		return err
	}
	cleanup = false

	moved, err := moveState(stageDir, filepath.Join(q.ready, dsn.ID))
	if err != nil && !moved {
		return err
	}
	q.mu.Lock()
	q.releaseReserveLocked(dsn.Size)
	q.noteAddedLocked(dsn)
	delete(q.transitioning, source.ID)
	delete(q.transitioning, dsn.ID)
	delete(q.requeues, source.ID)
	delete(q.requeues, dsn.ID)
	q.scheduleLocked(dsn)
	q.mu.Unlock()
	held = false
	owned = false
	source.DSNID = dsn.ID
	source.Revision = linked.Revision
	q.signal()
	if q.afterPublish != nil {
		q.afterPublish()
	}
	return err
}

func (q *Queue) publishStagedDSN(dsn *Envelope) (*Envelope, bool, error) {
	stageDir := filepath.Join(q.dsn, dsn.ID)
	if _, err := os.Stat(stageDir); errors.Is(err, os.ErrNotExist) {
		// No stage means the linked DSN was already published and may have
		// completed. The durable source link is sufficient evidence.
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	staged, err := q.loadDir(stageDir, dsn.ID)
	if err != nil {
		return nil, false, err
	}
	if staged.DSNSourceID != dsn.DSNSourceID || staged.DSNSourceIncarnation != dsn.DSNSourceIncarnation || staged.DSNGeneration != dsn.DSNGeneration {
		return nil, false, fmt.Errorf("%w: staged DSN identity mismatch", ErrIDConflict)
	}
	moved, err := moveState(stageDir, filepath.Join(q.ready, dsn.ID))
	if err != nil && !moved {
		return nil, false, err
	}
	return staged, true, err
}

// acceptAdd performs the sole Add acceptance transition. The marker already
// has a durable directory entry, so only its fixed-size contents need syncing.
// No fallible operation is reported after the successful Sync commit point.
func acceptAdd(path string) error {
	if len(addPending) != len(addAccepted) {
		panic("queue Add states must have equal length")
	}

	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := writeAddState(file, addAccepted); err != nil {
		return rollbackAdd(file, err)
	}
	if err := disk.SyncFile(file); err != nil {
		return rollbackAdd(file, err)
	}

	_ = file.Close()
	return nil
}

func rollbackAdd(file *os.File, cause error) error {
	// A failed commit must not leave accepted bytes recoverable after Add
	// reports failure. A successful rollback sync restores that invariant.
	if err := writeAddState(file, addPending); err != nil {
		return errors.Join(cause, fmt.Errorf("rollback add state: %w", err))
	}
	if err := disk.SyncFile(file); err != nil {
		return errors.Join(cause, fmt.Errorf("sync rolled-back add state: %w", err))
	}
	return cause
}

func writeAddState(file *os.File, state string) error {
	n, err := file.WriteAt([]byte(state), 0)
	if err != nil {
		return err
	}
	if n != len(state) {
		return io.ErrShortWrite
	}
	return nil
}

// Next blocks until a message is due for delivery or ctx is cancelled.
// The returned envelope is removed from the in-memory schedule but remains on
// disk under ready/ until Finish, Retry, or Bury.
func (q *Queue) Next(ctx context.Context) (*Envelope, error) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	for {
		q.mu.Lock()
		wait := time.Hour
		if q.pending.Len() > 0 {
			envelope := q.pending[0]
			delay := time.Until(envelope.NextAttempt)
			if delay <= 0 {
				heap.Pop(&q.pending)
				delete(q.scheduled, envelope.ID)
				q.mu.Unlock()
				return envelope, nil
			}
			wait = delay
		}
		q.mu.Unlock()

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-q.notify:
		case <-timer.C:
		}
	}
}

// Requeue puts an envelope back onto the schedule without disk I/O.
// Used when delivery is cancelled before a persistence attempt.
func (q *Queue) Requeue(envelope *Envelope) {
	q.mu.Lock()
	if _, transitioning := q.transitioning[envelope.ID]; transitioning {
		for _, queued := range q.requeues[envelope.ID] {
			if queued == envelope {
				q.mu.Unlock()
				return
			}
		}
		q.requeues[envelope.ID] = append(q.requeues[envelope.ID], envelope)
		q.mu.Unlock()
		return
	}
	added := q.scheduleLocked(envelope)
	q.mu.Unlock()
	if added {
		q.signal()
	}
}

// Retry persists the updated envelope and reschedules it.
// On persistence failure the envelope is NOT removed from recoverability:
// it remains under ready/ and is returned to the schedule so a subsequent
// Open recovers it. The error is returned to the caller.
func (q *Queue) Retry(envelope *Envelope) error {
	if err := q.rejectReadOnly(); err != nil {
		return err
	}
	if err := ValidateID(envelope.ID); err != nil {
		return err
	}
	if err := q.beginTransition(envelope.ID); err != nil {
		return err
	}
	owned := true
	defer func() {
		if owned {
			q.endTransition(envelope.ID)
		}
	}()
	publish := func() {
		q.mu.Lock()
		delete(q.transitioning, envelope.ID)
		delete(q.requeues, envelope.ID)
		added := q.scheduleLocked(envelope)
		q.mu.Unlock()
		owned = false
		if added {
			q.signal()
			if q.afterPublish != nil {
				q.afterPublish()
			}
		}
	}
	if err := validateEnvelope(envelope); err != nil {
		// Still reschedule so we do not strand.
		publish()
		return err
	}
	if err := q.storeReady(envelope); err != nil {
		// Leave bytes on disk; keep it schedulable.
		if !errors.Is(err, ErrIDConflict) {
			publish()
		}
		return err
	}
	publish()
	return nil
}

// Finish removes a fully handled message from the spool. Crash-safe: the
// directory is renamed into trash/ then removed. A crash after rename leaves
// a trash entry cleaned on Open.
func (q *Queue) Finish(envelope *Envelope) error {
	if err := q.rejectReadOnly(); err != nil {
		return err
	}
	if err := ValidateID(envelope.ID); err != nil {
		return err
	}
	if err := q.beginTransition(envelope.ID); err != nil {
		return err
	}
	defer q.endTransition(envelope.ID)
	src := filepath.Join(q.ready, envelope.ID)
	if err := q.matchReady(envelope); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dst := filepath.Join(q.trash, envelope.ID+"."+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err := disk.Mkdir(q.trash); err != nil {
		return err
	}
	moved, err := moveState(src, dst)
	if err != nil {
		if moved || errors.Is(err, os.ErrNotExist) {
			// Already gone — treat as success for idempotence.
			q.noteRemoved(envelope.ID)
			if !moved {
				return nil
			}
		}
		return err
	}
	q.noteRemoved(envelope.ID)
	if err := q.removeTrash(dst); err != nil {
		return fmt.Errorf("%w: %w", ErrCleanup, err)
	}
	return nil
}

// Bury moves an undeliverable message into the dead-letter directory atomically
// (single directory rename). Metadata is written first inside ready/.
func (q *Queue) Bury(envelope *Envelope) error {
	if err := q.rejectReadOnly(); err != nil {
		return err
	}
	if err := ValidateID(envelope.ID); err != nil {
		return err
	}
	if err := q.beginTransition(envelope.ID); err != nil {
		return err
	}
	owned := true
	defer func() {
		if owned {
			q.endTransition(envelope.ID)
		}
	}()
	reschedule := func() {
		q.mu.Lock()
		delete(q.transitioning, envelope.ID)
		delete(q.requeues, envelope.ID)
		added := q.scheduleLocked(envelope)
		q.mu.Unlock()
		owned = false
		if added {
			q.signal()
			if q.afterPublish != nil {
				q.afterPublish()
			}
		}
	}
	if err := validateEnvelope(envelope); err != nil {
		return err
	}
	src := filepath.Join(q.ready, envelope.ID)
	dst := filepath.Join(q.dead, envelope.ID)
	if err := q.matchReady(envelope); err != nil {
		if _, srcErr := os.Stat(src); errors.Is(srcErr, os.ErrNotExist) {
			dead, deadErr := q.loadAcceptedDir(dst, envelope.ID)
			if deadErr == nil {
				if dead.Incarnation != envelope.Incarnation || dead.Revision != envelope.Revision {
					return fmt.Errorf("%w: dead-letter identity changed", ErrIDConflict)
				}
				q.noteRemoved(envelope.ID)
				return nil
			}
			if !errors.Is(deadErr, os.ErrNotExist) {
				return deadErr
			}
		}
		if !errors.Is(err, ErrIDConflict) {
			reschedule()
		}
		return err
	}
	if _, err := os.Stat(dst); err == nil {
		reschedule()
		return fmt.Errorf("%w: dead-letter id %s already exists", ErrIDConflict, envelope.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		reschedule()
		return err
	}
	// Persist final status inside ready/ before the rename.
	if err := q.storeReady(envelope); err != nil {
		// Reschedule for recoverability; signal fatal to caller.
		if !errors.Is(err, ErrIDConflict) {
			reschedule()
		}
		return err
	}
	moved, err := moveState(src, dst)
	if err != nil {
		if moved {
			q.noteRemoved(envelope.ID)
		} else {
			reschedule()
		}
		return err
	}
	q.noteRemoved(envelope.ID)
	return nil
}

// ReviveDead moves a dead-letter item back to ready and schedules it.
func (q *Queue) ReviveDead(id string) (*Envelope, error) {
	if err := q.rejectReadOnly(); err != nil {
		return nil, err
	}
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	if err := q.beginTransition(id); err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			q.endTransition(id)
		}
	}()
	src := filepath.Join(q.dead, id)
	if err := acceptedDir(src); err != nil {
		return nil, err
	}
	env, err := q.loadDir(src, id)
	if err != nil {
		return nil, err
	}
	q.mu.Lock()
	if _, exists := q.accounted[id]; exists {
		q.mu.Unlock()
		return nil, fmt.Errorf("queue id %s is already ready", id)
	}
	if err := q.reserveLocked(env.Size, false); err != nil {
		q.mu.Unlock()
		return nil, err
	}
	q.mu.Unlock()
	held := true
	defer func() {
		if held {
			q.ReleaseReserve(env.Size)
		}
	}()

	for i := range env.Recipients {
		if env.Recipients[i].Status == StatusFailed {
			env.Recipients[i].Status = StatusPending
			env.Recipients[i].Detail = ""
			env.Recipients[i].Code = 0
		}
	}
	env.Attempts = 0
	env.LastError = ""
	env.NextAttempt = time.Now()
	if env.DSNSourceID == "" {
		if env.DSNGeneration == ^uint64(0) {
			return nil, errors.New("DSN generation overflow")
		}
		env.DSNGeneration++
		env.DSNID = ""
	}
	env.Revision++

	stagedMeta := filepath.Join(src, reviveMetaName)
	if err := q.writeMeta(stagedMeta, env); err != nil {
		return nil, errors.Join(err, removeAndSync(stagedMeta))
	}
	dst := filepath.Join(q.ready, id)
	moved, moveErr := moveState(src, dst)
	if moveErr != nil && !moved {
		return nil, errors.Join(moveErr, removeAndSync(stagedMeta))
	}
	activated, activateErr := moveState(filepath.Join(dst, reviveMetaName), filepath.Join(dst, metaName))
	if activateErr != nil && !activated {
		rolledBack, rollbackErr := moveState(dst, src)
		if rolledBack {
			cleanupErr := removeAndSync(filepath.Join(src, reviveMetaName))
			return nil, errors.Join(moveErr, activateErr, rollbackErr, cleanupErr)
		}
		committed, reconcileErr := q.writeMetaReconciled(filepath.Join(dst, metaName), env)
		if !committed {
			return nil, errors.Join(moveErr, activateErr, fmt.Errorf("rollback revive: %w", rollbackErr), reconcileErr)
		}
		cleanupErr := removeAndSync(filepath.Join(dst, reviveMetaName))
		activateErr = errors.Join(activateErr, fmt.Errorf("rollback revive: %w", rollbackErr), reconcileErr, cleanupErr)
	}
	if activateErr != nil {
		moveErr = errors.Join(moveErr, activateErr)
	}

	q.mu.Lock()
	q.releaseReserveLocked(env.Size)
	q.noteAddedLocked(env)
	delete(q.transitioning, id)
	delete(q.requeues, id)
	q.scheduleLocked(env)
	q.mu.Unlock()
	held = false
	owned = false
	q.signal()
	if q.afterPublish != nil {
		q.afterPublish()
	}
	return env, moveErr
}

// DeadIDs lists dead-letter entry IDs.
func (q *Queue) DeadIDs() ([]string, error) {
	entries, err := os.ReadDir(q.dead)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if err := ValidateID(e.Name()); err != nil {
			continue
		}
		ids = append(ids, e.Name())
	}
	return ids, nil
}

// LoadDead reads a dead-letter envelope by id.
func (q *Queue) LoadDead(id string) (*Envelope, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	return q.loadAcceptedDir(filepath.Join(q.dead, id), id)
}

// ExportDead copies the original message to w.
func (q *Queue) ExportDead(id string, w io.Writer) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	if _, err := q.loadAcceptedDir(filepath.Join(q.dead, id), id); err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(q.dead, id, bodyName))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// Reader opens the stored message body for a ready entry.
func (q *Queue) Reader(id string) (*os.File, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	if _, err := q.loadAcceptedDir(filepath.Join(q.ready, id), id); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(q.ready, id, bodyName), os.O_RDONLY, 0)
}

// ReadBody returns the full body bytes for ready or dead.
func (q *Queue) ReadBody(id string) ([]byte, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	ready := filepath.Join(q.ready, id)
	if _, err := q.loadAcceptedDir(ready, id); err == nil {
		return os.ReadFile(filepath.Join(ready, bodyName))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	dead := filepath.Join(q.dead, id)
	if _, err := q.loadAcceptedDir(dead, id); err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(dead, bodyName))
}

// Path returns the spool root.
func (q *Queue) Path() string { return q.root }

// DeadDir returns the dead-letter directory.
func (q *Queue) DeadDir() string { return q.dead }

func (q *Queue) schedule(envelope *Envelope) {
	q.mu.Lock()
	added := q.scheduleLocked(envelope)
	q.mu.Unlock()
	if added {
		q.signal()
	}
}

func (q *Queue) signal() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *Queue) scheduleLocked(envelope *Envelope) bool {
	accounted, exists := q.accounted[envelope.ID]
	if !exists || accounted.incarnation != envelope.Incarnation || accounted.revision != envelope.Revision {
		return false
	}
	if _, exists := q.scheduled[envelope.ID]; exists {
		return false
	}
	heap.Push(&q.pending, envelope)
	q.scheduled[envelope.ID] = struct{}{}
	return true
}

func (q *Queue) noteAddedLocked(envelope *Envelope) {
	if _, exists := q.accounted[envelope.ID]; exists {
		return
	}
	q.accounted[envelope.ID] = accountedEntry{
		size:        envelope.Size,
		incarnation: envelope.Incarnation,
		revision:    envelope.Revision,
	}
	q.count++
	q.bytes += envelope.Size
}

func (q *Queue) beginTransition(id string) error {
	return q.beginTransitions(id)
}

func (q *Queue) beginTransitions(ids ...string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, id := range ids {
		if _, exists := q.transitioning[id]; exists {
			return ErrQueueBusy
		}
	}
	for _, id := range ids {
		q.transitioning[id] = struct{}{}
	}
	return nil
}

func (q *Queue) endTransition(id string) {
	q.endTransitions(id)
}

func (q *Queue) endTransitions(ids ...string) {
	q.mu.Lock()
	added := false
	for _, id := range ids {
		delete(q.transitioning, id)
		for _, envelope := range q.requeues[id] {
			if q.scheduleLocked(envelope) {
				added = true
				break
			}
		}
		delete(q.requeues, id)
	}
	q.mu.Unlock()
	if added {
		q.signal()
	}
}

func (q *Queue) noteRemoved(id string) {
	q.mu.Lock()
	entry, exists := q.accounted[id]
	if exists {
		delete(q.accounted, id)
		delete(q.scheduled, id)
		delete(q.requeues, id)
		q.count--
		q.bytes -= entry.size
	}
	q.mu.Unlock()
}

func (q *Queue) storeReady(envelope *Envelope) error {
	dir := filepath.Join(q.ready, envelope.ID)
	if err := q.matchReady(envelope); err != nil {
		return err
	}
	path := filepath.Join(dir, metaName)
	updated := *envelope
	updated.Revision++
	committed, err := q.writeMetaReconciled(path, &updated)
	if !committed {
		return err
	}
	envelope.Revision = updated.Revision
	q.mu.Lock()
	if entry, exists := q.accounted[envelope.ID]; exists && entry.incarnation == envelope.Incarnation {
		entry.revision = envelope.Revision
		q.accounted[envelope.ID] = entry
	}
	q.mu.Unlock()
	return err
}

func (q *Queue) matchReady(envelope *Envelope) error {
	dir := filepath.Join(q.ready, envelope.ID)
	if err := acceptedDir(dir); err != nil {
		return err
	}
	current, err := q.loadDir(dir, envelope.ID)
	if err != nil {
		return err
	}
	if current.Incarnation != envelope.Incarnation {
		return fmt.Errorf("%w: queue incarnation changed", ErrIDConflict)
	}
	if current.Revision != envelope.Revision {
		return fmt.Errorf("%w: queue metadata changed", ErrIDConflict)
	}
	return nil
}

func acceptedDir(dir string) error {
	state, err := os.ReadFile(filepath.Join(dir, addStateName))
	if err != nil {
		return err
	}
	if string(state) != addAccepted {
		return errors.New("queue entry is not accepted")
	}
	return nil
}

// moveState reports whether the rename changed the live namespace even when a
// post-rename hook or parent sync returns an error.
func moveState(src, dst string) (bool, error) {
	err := disk.Rename(src, dst)
	if err == nil {
		return true, nil
	}
	_, srcErr := os.Stat(src)
	_, dstErr := os.Stat(dst)
	if errors.Is(srcErr, os.ErrNotExist) && dstErr == nil {
		return true, err
	}
	return false, err
}

func removeAndSync(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return disk.Sync(filepath.Dir(path))
}

func (q *Queue) writeMeta(path string, envelope *Envelope) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return disk.Write(path, body, 0600)
}

func (q *Queue) writeMetaReconciled(path string, envelope *Envelope) (bool, error) {
	body, err := json.Marshal(envelope)
	if err != nil {
		return false, err
	}
	if err := disk.Write(path, body, 0600); err != nil {
		visible, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Equal(visible, body) {
			return true, err
		}
		return false, errors.Join(err, readErr)
	}
	return true, nil
}

func (q *Queue) loadDir(dir, expectID string) (*Envelope, error) {
	metaPath := filepath.Join(dir, metaName)
	bodyPath := filepath.Join(dir, bodyName)

	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	env := new(Envelope)
	if err := json.Unmarshal(raw, env); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}
	if env.ID != expectID {
		return nil, fmt.Errorf("%w: id %q != directory %q", ErrInvalidID, env.ID, expectID)
	}
	if err := ValidateID(env.ID); err != nil {
		return nil, err
	}
	if err := validateEnvelope(env); err != nil {
		return nil, err
	}
	st, err := os.Lstat(bodyPath)
	if err != nil {
		return nil, fmt.Errorf("missing body: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("body is not a regular file")
	}
	if env.Size != st.Size() {
		return nil, fmt.Errorf("body size mismatch: metadata=%d actual=%d", env.Size, st.Size())
	}
	return env, nil
}

// Open loads an existing spool directory, creating it when needed.
// Acquires an exclusive lock on <directory>/.lock before recovery or
// scheduling. Call Close to release it.
// Corrupt entries are relocated to corrupt/ and returned via Queue.Corrupt.
func Open(directory string, limits Limits) (*Queue, error) {
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
		accounted:     make(map[string]accountedEntry),
		scheduled:     make(map[string]struct{}),
		transitioning: make(map[string]struct{}),
		requeues:      make(map[string][]*Envelope),
	}

	if err := disk.MkdirDurable(q.root); err != nil {
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

	for _, d := range []string{q.ready, q.dead, q.tmp, q.dsn, q.corr, q.trash} {
		if err := disk.MkdirDurable(d); err != nil {
			_ = q.Close()
			return nil, err
		}
	}

	if err := q.recoverTmp(); err != nil {
		_ = q.Close()
		return nil, err
	}
	if err := q.cleanTrash(); err != nil {
		q.Warnings = append(q.Warnings, fmt.Errorf("trash cleanup: %w", err))
	}
	if err := q.recoverDSN(); err != nil {
		_ = q.Close()
		return nil, err
	}
	if err := q.loadReady(); err != nil {
		_ = q.Close()
		return nil, err
	}
	return q, nil
}

// OpenReadOnly opens a spool for inspection without taking the exclusive lock
// and without tmp recovery, trash cleanup, or schedule load.
// Supported: DeadIDs, LoadDead, ExportDead, ReadBody, Path, DeadDir.
// Mutating methods return ErrReadOnly.
func OpenReadOnly(directory string) (*Queue, error) {
	return &Queue{
		root:          directory,
		ready:         filepath.Join(directory, dirReady),
		dead:          filepath.Join(directory, dirDead),
		tmp:           filepath.Join(directory, dirTmp),
		dsn:           filepath.Join(directory, dirDSN),
		corr:          filepath.Join(directory, dirCorrupt),
		trash:         filepath.Join(directory, dirTrash),
		notify:        make(chan struct{}, 1),
		accounted:     make(map[string]accountedEntry),
		scheduled:     make(map[string]struct{}),
		transitioning: make(map[string]struct{}),
		requeues:      make(map[string][]*Envelope),
		readOnly:      true,
	}, nil
}

// Close releases the exclusive spool lock.
func (q *Queue) Close() error {
	if q == nil || q.lock == nil {
		return nil
	}
	err := q.lock.Close()
	q.lock = nil
	return err
}

// OpenDefault is Open with unlimited quotas.
func OpenDefault(directory string) (*Queue, error) {
	return Open(directory, Limits{})
}

func (q *Queue) recoverTmp() error {
	entries, err := os.ReadDir(q.tmp)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			_ = os.Remove(filepath.Join(q.tmp, e.Name()))
			continue
		}
		id := e.Name()
		dir := filepath.Join(q.tmp, id)
		// tmp entries have not crossed Add's acceptance point. Completeness is
		// not evidence of acceptance, so preserve them only for diagnosis.
		if qerr := q.quarantineDir(dir, id+"-uncommitted"); qerr != nil {
			return qerr
		}
		q.Corrupt = append(q.Corrupt, fmt.Errorf("tmp %s: interrupted uncommitted add", id))
	}
	return disk.Sync(q.tmp)
}

func (q *Queue) cleanTrash() error {
	entries, err := os.ReadDir(q.trash)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if err := disk.RemoveAll(filepath.Join(q.trash, e.Name())); err != nil {
			errs = append(errs, fmt.Errorf("remove trash %s: %w", e.Name(), err))
		}
	}
	if err := disk.Sync(q.trash); err != nil {
		errs = append(errs, fmt.Errorf("sync trash: %w", err))
	}
	return errors.Join(errs...)
}

func (q *Queue) recoverDSN() error {
	entries, err := os.ReadDir(q.dsn)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(q.dsn, entry.Name())
		if !entry.IsDir() {
			if err := q.quarantineFile(path, entry.Name()+"-dsn-stray"); err != nil {
				return err
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("stray file in dsn: %s", entry.Name()))
			continue
		}
		id := entry.Name()
		if err := acceptedDir(path); err != nil {
			if qerr := q.quarantineDSNStage(path, id, "uncommitted", err); qerr != nil {
				return qerr
			}
			continue
		}
		dsn, err := q.loadDir(path, id)
		if err != nil {
			if qerr := q.quarantineDSNStage(path, id, "invalid", err); qerr != nil {
				return qerr
			}
			continue
		}
		source, err := q.loadDir(filepath.Join(q.ready, dsn.DSNSourceID), dsn.DSNSourceID)
		if err != nil || source.Incarnation != dsn.DSNSourceIncarnation || source.DSNID != dsn.ID || source.DSNGeneration != dsn.DSNGeneration {
			cause := errors.New("source link missing or invalid")
			if qerr := q.quarantineDSNStage(path, id, "orphan", cause); qerr != nil {
				return qerr
			}
			continue
		}
		readyDir := filepath.Join(q.ready, id)
		if _, err := os.Stat(readyDir); err == nil {
			existing, loadErr := q.loadDir(readyDir, id)
			if loadErr == nil && existing.Incarnation == dsn.Incarnation && existing.DSNSourceID == dsn.DSNSourceID && existing.DSNSourceIncarnation == dsn.DSNSourceIncarnation && existing.DSNGeneration == dsn.DSNGeneration {
				if err := q.quarantineDir(path, id+"-dsn-duplicate"); err != nil {
					return err
				}
				q.Corrupt = append(q.Corrupt, fmt.Errorf("staged DSN %s: duplicate ready entry", id))
				continue
			}
			cause := fmt.Errorf("%w: ready DSN collision", ErrIDConflict)
			if err := q.quarantineDSNStage(path, id, "collision", cause); err != nil {
				return err
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		moved, err := moveState(path, readyDir)
		if err != nil {
			if moved {
				return fmt.Errorf("publish recovered DSN %s: %w", id, err)
			}
			return err
		}
	}
	return nil
}

func (q *Queue) quarantineDSNStage(stage, id, suffix string, cause error) error {
	entries, err := os.ReadDir(q.ready)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sourceDir := filepath.Join(q.ready, entry.Name())
		raw, err := os.ReadFile(filepath.Join(sourceDir, metaName))
		if err != nil {
			continue
		}
		var source Envelope
		if json.Unmarshal(raw, &source) != nil || source.DSNID != id {
			continue
		}
		if err := q.quarantineDir(sourceDir, source.ID+"-dsn-source"); err != nil {
			return err
		}
		q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: linked staged DSN %s is invalid", source.ID, id))
	}
	if err := q.quarantineDir(stage, id+"-dsn-"+suffix); err != nil {
		return err
	}
	q.Corrupt = append(q.Corrupt, fmt.Errorf("staged DSN %s: %w", id, cause))
	return nil
}

func (q *Queue) loadReady() error {
	entries, err := os.ReadDir(q.ready)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			// stray file
			if err := q.quarantineFile(filepath.Join(q.ready, e.Name()), e.Name()+"-stray"); err != nil {
				return err
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("stray file in ready: %s", e.Name()))
			continue
		}
		id := e.Name()
		dir := filepath.Join(q.ready, id)
		if err := ValidateID(id); err != nil {
			if qerr := q.quarantineDir(dir, "badid-"+sanitize(id)); qerr != nil {
				return qerr
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: %w", id, err))
			continue
		}
		state, err := os.ReadFile(filepath.Join(dir, addStateName))
		if err != nil {
			if qerr := q.quarantineDir(dir, id); qerr != nil {
				return qerr
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: read add state: %w", id, err))
			continue
		}
		if string(state) != addAccepted {
			if qerr := q.quarantineDir(dir, id+"-uncommitted"); qerr != nil {
				return qerr
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: uncommitted or invalid add state", id))
			continue
		}
		stagedMeta := filepath.Join(dir, reviveMetaName)
		if _, err := os.Stat(stagedMeta); err == nil {
			moved, moveErr := moveState(stagedMeta, filepath.Join(dir, metaName))
			if moveErr != nil && !moved {
				return fmt.Errorf("complete revive %s: %w", id, moveErr)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect revive %s: %w", id, err)
		}
		env, err := q.loadDir(dir, id)
		if err != nil {
			if qerr := q.quarantineDir(dir, id); qerr != nil {
				return qerr
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: %w", id, err))
			continue
		}
		deadDir := filepath.Join(q.dead, id)
		dead, deadErr := q.loadAcceptedDir(deadDir, id)
		if deadErr == nil {
			if dead.Incarnation != env.Incarnation || dead.Revision != env.Revision {
				return fmt.Errorf("%w: ready and dead entries differ for %s", ErrIDConflict, id)
			}
			if qerr := q.quarantineDir(dir, id+"-dead-duplicate"); qerr != nil {
				return qerr
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: duplicate dead-letter entry", id))
			continue
		}
		if !errors.Is(deadErr, os.ErrNotExist) {
			if qerr := q.quarantineDir(deadDir, id+"-invalid-dead"); qerr != nil {
				return qerr
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("dead %s: %w", id, deadErr))
		}
		q.noteAddedLocked(env)
		q.scheduleLocked(env)
	}
	return nil
}

func (q *Queue) loadAcceptedDir(dir, expectID string) (*Envelope, error) {
	if err := acceptedDir(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, statErr := os.Stat(dir); statErr == nil {
				return nil, errors.New("queue entry is missing accepted state")
			} else {
				return nil, statErr
			}
		}
		return nil, err
	}
	return q.loadDir(dir, expectID)
}

func (q *Queue) removeTrash(path string) error {
	removeErr := disk.RemoveAll(path)
	syncErr := disk.Sync(q.trash)
	return errors.Join(removeErr, syncErr)
}

func (q *Queue) quarantineDir(src, name string) error {
	if err := disk.Mkdir(q.corr); err != nil {
		return err
	}
	dst := filepath.Join(q.corr, name+"."+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err := disk.Rename(src, dst); err != nil {
		// fallback copy-ish remove
		return fmt.Errorf("quarantine %s: %w", src, err)
	}
	if err := disk.Sync(filepath.Dir(src)); err != nil {
		return fmt.Errorf("sync quarantine source %s: %w", src, err)
	}
	return nil
}

func (q *Queue) quarantineFile(src, name string) error {
	if err := disk.Mkdir(q.corr); err != nil {
		return err
	}
	dstDir := filepath.Join(q.corr, name+"."+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err := disk.Mkdir(dstDir); err != nil {
		return err
	}
	dst := filepath.Join(dstDir, filepath.Base(src))
	if err := os.Rename(src, dst); err != nil {
		// cross-device rare; read-write
		data, rerr := os.ReadFile(src)
		if rerr != nil {
			return rerr
		}
		if werr := disk.Write(dst, data, 0600); werr != nil {
			return werr
		}
		_ = os.Remove(src)
	}
	_ = disk.Sync(q.corr)
	return nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

func validateEnvelope(e *Envelope) error {
	if err := ValidateID(e.ID); err != nil {
		return err
	}
	if len(e.Incarnation) != 32 {
		return errors.New("invalid queue incarnation")
	}
	if _, err := hex.DecodeString(e.Incarnation); err != nil {
		return errors.New("invalid queue incarnation")
	}
	if e.Revision == 0 {
		return errors.New("invalid queue revision")
	}
	if e.Username == "" {
		return errors.New("missing username")
	}
	if e.DSNSourceID != "" {
		if err := ValidateID(e.DSNSourceID); err != nil {
			return fmt.Errorf("DSN source: %w", err)
		}
		if len(e.DSNSourceIncarnation) != 32 {
			return errors.New("invalid DSN source incarnation")
		}
		if _, err := hex.DecodeString(e.DSNSourceIncarnation); err != nil {
			return errors.New("invalid DSN source incarnation")
		}
		if e.ID != DSNID(e.DSNSourceID, e.DSNSourceIncarnation, e.DSNGeneration) {
			return fmt.Errorf("%w: derived DSN ID mismatch", ErrIDConflict)
		}
		if e.DSNID != "" {
			return errors.New("DSN cannot link another DSN")
		}
		if e.Sender != "" {
			return errors.New("DSN sender must be empty")
		}
	} else if e.Sender != "" {
		if e.DSNSourceIncarnation != "" {
			return errors.New("DSN source incarnation without source ID")
		}
		if err := validateAddress(e.Sender); err != nil {
			return fmt.Errorf("sender: %w", err)
		}
	} else {
		return errors.New("missing sender")
	}
	if e.DSNID != "" && e.DSNID != DSNID(e.ID, e.Incarnation, e.DSNGeneration) {
		return fmt.Errorf("%w: source DSN link mismatch", ErrIDConflict)
	}
	if len(e.Recipients) == 0 {
		return errors.New("no recipients")
	}
	if e.Created.IsZero() {
		return errors.New("missing created timestamp")
	}
	if e.Attempts < 0 {
		return errors.New("negative attempts")
	}
	if e.Size < 0 {
		return errors.New("negative size")
	}
	needUTF8 := false
	if e.Sender != "" && addressHasNonASCII(e.Sender) {
		needUTF8 = true
	}
	for i := range e.Recipients {
		r := &e.Recipients[i]
		if err := validateAddress(r.Address); err != nil {
			return fmt.Errorf("recipient[%d]: %w", i, err)
		}
		if addressHasNonASCII(r.Address) {
			needUTF8 = true
		}
		routing, err := mailbox.DomainOf(r.Address)
		if err != nil {
			return fmt.Errorf("recipient[%d]: %w", i, err)
		}
		if r.Domain == "" {
			r.Domain = routing
		} else {
			// Accept a stored routing domain only when it normalizes to the same A-label.
			// Unicode routing domains left by older builds are rewritten to the A-label.
			stored, err := mailbox.RoutingDomain(r.Domain)
			if err != nil || stored != routing {
				return fmt.Errorf("recipient[%d]: domain mismatch", i)
			}
			r.Domain = routing
		}
		switch r.Status {
		case StatusPending, StatusSent, StatusFailed:
		case "":
			r.Status = StatusPending
		default:
			return fmt.Errorf("recipient[%d]: invalid status %q", i, r.Status)
		}
	}
	// Non-ASCII envelope addresses require the SMTPUTF8 flag so outbound MAIL/RCPT
	// never emit UTF-8 without the SMTPUTF8 MAIL parameter. ASCII envelopes may set
	// the flag when headers independently require it; the flag is never cleared here.
	if needUTF8 && !e.SMTPUTF8 {
		return errors.New("SMTPUTF8 required for non-ASCII envelope address")
	}
	return nil
}

// addressHasNonASCII reports whether addr contains any octet above 0x7F.
// Addresses must already be valid UTF-8 (enforced by validateAddress).
func addressHasNonASCII(addr string) bool {
	for i := 0; i < len(addr); i++ {
		if addr[i] >= 0x80 {
			return true
		}
	}
	return false
}

func validateAddress(addr string) error {
	if addr == "" {
		return errors.New("empty address")
	}
	if !utf8.ValidString(addr) {
		return errors.New("invalid utf-8")
	}
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return errors.New("missing @domain")
	}
	if strings.ContainsAny(addr, " \t\r\n") {
		return errors.New("whitespace in address")
	}
	return nil
}
