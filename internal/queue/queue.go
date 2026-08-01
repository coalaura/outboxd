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
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
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

// MinimumSpoolEmergencyBytes guarantees room for one bounded DSN transaction,
// source metadata replacement, and a terminal namespace transition.
const MinimumSpoolEmergencyBytes int64 = 16 << 20

var terminalSpoolReserve = 4 * disk.AllocationSize(0)

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

	maxAddStateBytes       = 64
	maxEnvelopeMetadata    = 4 << 20
	maxEnvelopeRecipients  = 1000
	maxEnvelopeStringBytes = 4096
	maxEnvelopeDetailBytes = 64 << 10
	maxEnvelopeAttempts    = 1 << 20
	maxEnvelopeRevision    = math.MaxUint64 - 1
)

// idPattern accepts the envelope IDs this process generates and previously
// generated forms. Paths, separators and traversal sequences are rejected.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,190}$`)

// Recipient is one envelope recipient and its delivery outcome.
type Recipient struct {
	Address      string `json:"address"`
	Domain       string `json:"domain"`
	Status       Status `json:"status"`
	Detail       string `json:"detail,omitempty"`
	Code         int    `json:"code,omitempty"`
	EnhancedCode string `json:"enhanced_code,omitempty"`
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

// Limits caps the durable queue. MaxBytes is the logical size of message
// bodies in ready/. MaxSpoolBytes is the hard physical limit across every
// queue namespace. Zero means unlimited for that dimension.
type Limits struct {
	MaxMessages         int
	MaxBytes            int64
	MaxSpoolBytes       int64
	SpoolEmergencyBytes int64
	MinFreeDisk         int64
	DeadRetention       time.Duration
	CorruptRetention    time.Duration
}

// PhysicalStats describes conservative spool allocation, including active
// reservations. HighWater is true once ordinary writes are in emergency
// headroom or the hard limit is at least 90 percent consumed.
type PhysicalStats struct {
	Used      int64
	Reserved  int64
	Limit     int64
	Emergency int64
	HighWater bool
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
	spoolMu       sync.Mutex
	pending       schedule
	notify        chan struct{}
	closeSignal   chan struct{}
	count         int
	bytes         int64
	accounted     map[string]accountedEntry
	scheduled     map[string]struct{}
	transitioning map[string]struct{}
	requeues      map[string][]*Envelope
	reserved      int   // in-flight Add reservations (count)
	resBytes      int64 // in-flight Add reservations (bytes)
	spoolBytes    int64 // conservative allocation across all namespaces
	spoolReserved int64 // in-flight physical allocation reservations
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

// SpoolStats returns conservative physical allocation across ready, tmp, dsn,
// dead, corrupt, and trash, including concurrent reservations.
func (q *Queue) SpoolStats() PhysicalStats {
	if q == nil || q.beginOperation() != nil {
		return PhysicalStats{}
	}
	defer q.endOperation()
	q.mu.Lock()
	defer q.mu.Unlock()
	stats := PhysicalStats{
		Used:      q.spoolBytes,
		Reserved:  q.spoolReserved,
		Limit:     q.limits.MaxSpoolBytes,
		Emergency: q.limits.SpoolEmergencyBytes,
	}
	total, ok := checkedAddInt64(stats.Used, stats.Reserved)
	if !ok {
		total = math.MaxInt64
	}
	ordinary := stats.Limit - stats.Emergency
	stats.HighWater = stats.Limit > 0 && (total >= ordinary || total >= stats.Limit-stats.Limit/10)
	return stats
}

// Reserve holds capacity for an in-progress Add so concurrent submissions
// cannot overshoot quotas. Release with ReleaseReserve if Add is abandoned.
func (q *Queue) Reserve(size int64) error {
	if err := q.beginOperation(); err != nil {
		return err
	}
	defer q.endOperation()
	if err := q.rejectReadOnly(); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.reserveLocked(size, size, false, false)
}

// reserveLocked checks logical and physical quotas. Emergency operations may
// consume the configured reserve but never the hard spool or free-space floor.
func (q *Queue) reserveLocked(size, physical int64, exempt, emergency bool) error {
	if size < 0 {
		return errors.New("negative reservation size")
	}
	if physical < 0 {
		return errors.New("negative physical reservation size")
	}
	used, ok := checkedAddInt(q.count, q.reserved)
	if !ok || used == math.MaxInt {
		return ErrQueueFull
	}
	usedBytes, ok := checkedAddInt64(q.bytes, q.resBytes)
	if !ok {
		return ErrQueueFull
	}
	totalBytes, ok := checkedAddInt64(usedBytes, size)
	if !ok {
		return ErrQueueFull
	}
	reservedBytes, ok := checkedAddInt64(q.resBytes, size)
	if !ok {
		return ErrQueueFull
	}
	if !exempt {
		if q.limits.MaxMessages > 0 && used >= q.limits.MaxMessages {
			return ErrQueueFull
		}
		if q.limits.MaxBytes > 0 && totalBytes > q.limits.MaxBytes {
			return ErrQueueFull
		}
	}
	if err := q.reservePhysicalLocked(physical, emergency); err != nil {
		return err
	}
	q.reserved++
	q.resBytes = reservedBytes
	return nil
}

// ReleaseReserve undoes Reserve.
func (q *Queue) ReleaseReserve(size int64) {
	if q == nil || q.beginOperation() != nil {
		return
	}
	defer q.endOperation()
	q.mu.Lock()
	defer q.mu.Unlock()
	q.releaseReserveLocked(size, size)
}

func (q *Queue) releaseReserveLocked(size, physical int64) {
	if size < 0 {
		return
	}
	if q.reserved > 0 {
		q.reserved--
	}
	if size > q.resBytes {
		q.resBytes = 0
	} else {
		q.resBytes -= size
	}
	if physical > q.spoolReserved {
		q.spoolReserved = 0
	} else {
		q.spoolReserved -= physical
	}
}

func (q *Queue) releaseReserve(size, physical int64) {
	q.mu.Lock()
	q.releaseReserveLocked(size, physical)
	q.mu.Unlock()
}

func estimateEntryAllocation(bodySize int64, metadataSize int) int64 {
	parts := []int64{
		disk.AllocationSize(0),
		disk.AllocationSize(bodySize),
		disk.AllocationSize(int64(metadataSize)),
		disk.AllocationSize(int64(len(addAccepted))),
		// tmp/ and ready/ may each cross an allocation boundary.
		2 * disk.AllocationSize(0),
	}
	var total int64
	for _, part := range parts {
		var ok bool
		total, ok = checkedAddInt64(total, part)
		if !ok {
			return math.MaxInt64
		}
	}
	return total
}

func (q *Queue) holdPhysical(bytes int64, emergency bool) (func(), error) {
	q.mu.Lock()
	err := q.reservePhysicalLocked(bytes, emergency)
	q.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return func() {
		q.mu.Lock()
		q.commitPhysicalLocked(bytes)
		q.mu.Unlock()
	}, nil
}

func (q *Queue) commitPhysicalLocked(bytes int64) {
	if bytes > q.spoolReserved {
		q.spoolReserved = 0
	} else {
		q.spoolReserved -= bytes
	}
	q.addPhysicalLocked(bytes)
}

func (q *Queue) addPhysicalLocked(bytes int64) {
	if bytes <= 0 {
		return
	}
	total, ok := checkedAddInt64(q.spoolBytes, bytes)
	if !ok {
		q.spoolBytes = math.MaxInt64
		return
	}
	q.spoolBytes = total
}

func (q *Queue) removePhysical(bytes int64) {
	if bytes <= 0 {
		return
	}
	q.mu.Lock()
	if bytes >= q.spoolBytes {
		q.spoolBytes = 0
	} else {
		q.spoolBytes -= bytes
	}
	q.mu.Unlock()
}

func (q *Queue) reservePhysicalLocked(physical int64, emergency bool) error {
	if physical < 0 {
		return errors.New("negative physical reservation size")
	}
	physicalReserved, ok := checkedAddInt64(q.spoolReserved, physical)
	if !ok {
		return ErrSpoolFull
	}
	physicalTotal, ok := checkedAddInt64(q.spoolBytes, physicalReserved)
	if !ok {
		return ErrSpoolFull
	}
	if q.limits.MaxSpoolBytes > 0 {
		limit := q.limits.MaxSpoolBytes
		if !emergency {
			limit -= q.limits.SpoolEmergencyBytes
		} else {
			// Always retain enough room for ready -> trash -> removal. Operations
			// that only free space do not reserve and may use this final margin.
			limit -= terminalSpoolReserve
		}
		if limit < 0 || physicalTotal > limit {
			return ErrSpoolFull
		}
	}
	if q.limits.MinFreeDisk > 0 && q.FreeDisk != nil {
		free, err := q.FreeDisk(q.root)
		if err != nil {
			return err
		}
		floor := q.limits.MinFreeDisk
		if !emergency {
			floor, ok = checkedAddInt64(floor, q.limits.SpoolEmergencyBytes)
			if !ok {
				return ErrInsufficientDisk
			}
		}
		if free < floor || physicalReserved > free-floor {
			return ErrInsufficientDisk
		}
	}
	q.spoolReserved = physicalReserved
	return nil
}

func checkedAddInt(a, b int) (int, bool) {
	if b > 0 && a > math.MaxInt-b {
		return 0, false
	}
	if b < 0 && a < math.MinInt-b {
		return 0, false
	}
	return a + b, true
}

func checkedAddInt64(a, b int64) (int64, bool) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, false
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, false
	}
	return a + b, true
}

var (
	// ErrQueueFull is returned when message count or byte quotas are exhausted.
	ErrQueueFull = errors.New("queue full")
	// ErrInsufficientDisk is returned when free disk is below the threshold.
	ErrInsufficientDisk = errors.New("insufficient free disk space")
	// ErrSpoolFull is returned when the physical spool limit is exhausted.
	ErrSpoolFull = errors.New("physical spool full")
	// ErrInvalidID is returned for unusable queue identifiers.
	ErrInvalidID = errors.New("invalid queue id")
	// ErrReadOnly is returned when a mutating method is called on a read-only queue.
	ErrReadOnly = errors.New("queue opened read-only")
	// ErrQueueBusy is returned when another operation owns the same queue ID.
	ErrQueueBusy = errors.New("queue id is busy")
	// ErrQueueClosed is returned after queue shutdown begins.
	ErrQueueClosed = errors.New("queue closed")
	// ErrIDConflict is returned when an ID names a different durable queue item.
	ErrIDConflict = errors.New("queue id conflict")
	// ErrCleanup reports that terminal state committed but garbage cleanup did not.
	ErrCleanup = errors.New("queue cleanup incomplete")
)

// IsStoragePressure reports errors that are recoverable by freeing spool or
// filesystem capacity.
func IsStoragePressure(err error) bool {
	if errors.Is(err, ErrSpoolFull) || errors.Is(err, ErrInsufficientDisk) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// ENOSPC/EDQUOT on common Unix platforms and ERROR_DISK_FULL on Windows.
		return errno == 28 || errno == 122 || errno == 112
	}
	return false
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
		if err := q.refreshSpoolUsage(); err != nil {
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
	if err := q.beginOperation(); err != nil {
		return err
	}
	defer q.endOperation()
	if err := q.rejectReadOnly(); err != nil {
		return err
	}
	if envelope == nil {
		return errors.New("missing envelope")
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
	if err := q.startMutation(); err != nil {
		return err
	}
	mutationHeld := true
	defer func() {
		if mutationHeld {
			q.finishMutation()
		}
	}()
	q.mu.Lock()
	_, blocked := q.blocked[envelope.ID]
	_, exists := q.accounted[envelope.ID]
	q.mu.Unlock()
	if blocked {
		return fmt.Errorf("%w: queue id %s is blocked by an unresolved corrupt entry", ErrIDConflict, envelope.ID)
	}
	if exists {
		return fmt.Errorf("%w: queue id %s is already ready", ErrIDConflict, envelope.ID)
	}
	readyDir := filepath.Join(q.ready, envelope.ID)
	if _, err := os.Stat(readyDir); err == nil {
		state, stateErr := readBoundedRegular(filepath.Join(readyDir, addStateName), maxAddStateBytes)
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
	meta, err := marshalEnvelope(envelope)
	if err != nil {
		return err
	}
	physical := estimateEntryAllocation(envelope.Size, len(meta))

	// Capacity check accounts for concurrent in-progress connections via reserved.
	q.mu.Lock()
	if err := q.reserveLocked(envelope.Size, physical, false, false); err != nil {
		q.mu.Unlock()
		return err
	}
	q.mu.Unlock()

	held := true
	defer func() {
		if held {
			q.releaseReserve(envelope.Size, physical)
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
			state, readErr := readBoundedRegular(filepath.Join(readyDir, addStateName), maxAddStateBytes)
			if readErr != nil || string(state) != addAccepted {
				return errors.Join(err, fmt.Errorf("quarantine failed add: %w", abortErr), readErr)
			}
		}
	}

	success = true
	held = false
	q.finishMutation()
	mutationHeld = false

	q.mu.Lock()
	q.releaseReserveLocked(envelope.Size, physical)
	q.addPhysicalLocked(physical)
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
	if err := q.beginOperation(); err != nil {
		return err
	}
	defer q.endOperation()
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
	if err := q.startMutation(); err != nil {
		return err
	}
	mutationHeld := true
	defer func() {
		if mutationHeld {
			q.finishMutation()
		}
	}()
	q.mu.Lock()
	_, sourceBlocked := q.blocked[source.ID]
	_, dsnBlocked := q.blocked[dsn.ID]
	q.mu.Unlock()
	if sourceBlocked || dsnBlocked {
		return fmt.Errorf("%w: DSN source or destination is blocked by unresolved corruption", ErrIDConflict)
	}

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
			q.finishMutation()
			mutationHeld = false
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
	meta, err := marshalEnvelope(dsn)
	if err != nil {
		return err
	}
	linked := *source
	linked.DSNID = dsn.ID
	if err := validateEnvelope(&linked); err != nil {
		return err
	}
	linkedMeta, err := marshalEnvelope(&linked)
	if err != nil {
		return err
	}
	physical, ok := checkedAddInt64(
		estimateEntryAllocation(dsn.Size, len(meta)),
		disk.AllocationSize(int64(len(linkedMeta))+disk.AllocationSize(0))+disk.AllocationSize(0),
	)
	if !ok {
		return ErrSpoolFull
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
		stageBytes, _ := disk.AllocatedBytes(stageDir)
		if err := os.RemoveAll(stageDir); err != nil {
			return err
		}
		if err := disk.Sync(q.dsn); err != nil {
			return err
		}
		q.removePhysical(stageBytes)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	q.mu.Lock()
	if err := q.reserveLocked(dsn.Size, physical, true, true); err != nil {
		q.mu.Unlock()
		return err
	}
	q.mu.Unlock()
	held := true
	physicalHeld := physical
	defer func() {
		if held {
			q.releaseReserve(dsn.Size, physicalHeld)
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
	if err := disk.Write(filepath.Join(stageDir, metaName), meta, 0600); err != nil {
		return err
	}
	if err := disk.Sync(stageDir); err != nil {
		return err
	}
	if err := acceptAdd(filepath.Join(stageDir, addStateName)); err != nil {
		return err
	}
	// The accepted stage remains recoverable across every later error. Move its
	// conservative reservation into committed usage before linking the source.
	q.mu.Lock()
	q.commitPhysicalLocked(physicalHeld)
	q.mu.Unlock()
	physicalHeld = 0

	storeErr := q.storeReady(&linked)
	if storeErr != nil && linked.Revision == source.Revision {
		// Preserve the complete stage. Startup decides whether the source update
		// committed and either publishes or quarantines it.
		cleanup = false
		q.mu.Lock()
		q.requeues[source.ID] = append(q.requeues[source.ID], cloneEnvelope(durableSource))
		q.mu.Unlock()
		return storeErr
	}
	cleanup = false

	moved, err := moveState(stageDir, filepath.Join(q.ready, dsn.ID))
	if err != nil && !moved {
		return err
	}
	q.finishMutation()
	mutationHeld = false
	q.mu.Lock()
	q.releaseReserveLocked(dsn.Size, physicalHeld)
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
	return errors.Join(storeErr, err)
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
	if err := q.beginOperation(); err != nil {
		return nil, err
	}
	defer q.endOperation()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	for {
		q.mu.Lock()
		if q.closing {
			q.mu.Unlock()
			return nil, ErrQueueClosed
		}
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
		case <-q.closeSignal:
			return nil, ErrQueueClosed
		case <-q.notify:
		case <-timer.C:
		}
	}
}

// Requeue puts an envelope back onto the schedule without disk I/O.
// Used when delivery is cancelled before a persistence attempt.
func (q *Queue) Requeue(envelope *Envelope) {
	if envelope == nil || q == nil || q.beginOperation() != nil {
		return
	}
	defer q.endOperation()
	q.mu.Lock()
	if _, transitioning := q.transitioning[envelope.ID]; transitioning {
		for _, queued := range q.requeues[envelope.ID] {
			if queued.Incarnation == envelope.Incarnation && queued.Revision == envelope.Revision {
				q.mu.Unlock()
				return
			}
		}
		q.requeues[envelope.ID] = append(q.requeues[envelope.ID], cloneEnvelope(envelope))
		q.mu.Unlock()
		return
	}
	added := q.scheduleLocked(envelope)
	q.mu.Unlock()
	if added {
		q.signal()
	}
}

// RequeueAfter keeps a recoverable entry in memory but prevents a storage
// pressure failure from immediately cycling all delivery workers.
func (q *Queue) RequeueAfter(envelope *Envelope, delay time.Duration) {
	if envelope == nil || q == nil || q.beginOperation() != nil {
		return
	}
	defer q.endOperation()
	deferred := cloneEnvelope(envelope)
	deferred.NextAttempt = time.Now().Add(delay)
	q.mu.Lock()
	for i, queued := range q.pending {
		if queued.ID == envelope.ID {
			heap.Remove(&q.pending, i)
			delete(q.scheduled, envelope.ID)
			break
		}
	}
	added := q.scheduleLocked(deferred)
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
	if err := q.beginOperation(); err != nil {
		return err
	}
	defer q.endOperation()
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
	if err := q.startMutation(); err != nil {
		return err
	}
	mutationHeld := true
	defer func() {
		if mutationHeld {
			q.finishMutation()
		}
	}()
	publish := func() {
		if mutationHeld {
			q.finishMutation()
			mutationHeld = false
		}
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
		// Reschedule the durable version rather than caller-mutated invalid data.
		if durable, loadErr := q.loadAcceptedDir(filepath.Join(q.ready, envelope.ID), envelope.ID); loadErr == nil {
			envelope = durable
		}
		publish()
		return err
	}
	meta, err := marshalEnvelope(envelope)
	if err != nil {
		publish()
		return err
	}
	release, err := q.holdPhysical(disk.AllocationSize(int64(len(meta))+disk.AllocationSize(0))+disk.AllocationSize(0), true)
	if err != nil {
		publish()
		return err
	}
	defer release()
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
	if err := q.beginOperation(); err != nil {
		return err
	}
	defer q.endOperation()
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
	if err := q.startMutation(); err != nil {
		return err
	}
	defer q.finishMutation()
	src := filepath.Join(q.ready, envelope.ID)
	if err := q.matchReady(envelope); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entryBytes, _ := disk.AllocatedBytes(src)
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
	q.removePhysical(entryBytes)
	return nil
}

// Bury moves an undeliverable message into the dead-letter directory atomically
// (single directory rename). Metadata is written first inside ready/.
func (q *Queue) Bury(envelope *Envelope) error {
	if err := q.beginOperation(); err != nil {
		return err
	}
	defer q.endOperation()
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
	if err := q.startMutation(); err != nil {
		return err
	}
	mutationHeld := true
	defer func() {
		if mutationHeld {
			q.finishMutation()
		}
	}()
	reschedule := func() {
		if mutationHeld {
			q.finishMutation()
			mutationHeld = false
		}
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
		// Reschedule the durable version rather than caller-mutated invalid data.
		if durable, loadErr := q.loadAcceptedDir(filepath.Join(q.ready, envelope.ID), envelope.ID); loadErr == nil {
			envelope = durable
		}
		reschedule()
		return err
	}
	meta, err := marshalEnvelope(envelope)
	if err != nil {
		reschedule()
		return err
	}
	release, err := q.holdPhysical(disk.AllocationSize(int64(len(meta))+disk.AllocationSize(0))+disk.AllocationSize(0), true)
	if err != nil {
		reschedule()
		return err
	}
	defer release()
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
	if err := q.beginOperation(); err != nil {
		return nil, err
	}
	defer q.endOperation()
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
	if err := q.startMutation(); err != nil {
		return nil, err
	}
	mutationHeld := true
	defer func() {
		if mutationHeld {
			q.finishMutation()
		}
	}()
	q.mu.Lock()
	_, blocked := q.blocked[id]
	q.mu.Unlock()
	if blocked {
		return nil, fmt.Errorf("%w: queue id %s is blocked by an unresolved corrupt entry", ErrIDConflict, id)
	}
	src := filepath.Join(q.dead, id)
	if err := acceptedDir(src); err != nil {
		return nil, err
	}
	env, err := q.loadDir(src, id)
	if err != nil {
		return nil, err
	}
	nextRevision, err := incrementRevision(env.Revision)
	if err != nil {
		return nil, err
	}
	if env.DSNSourceID == "" && env.DSNGeneration == math.MaxUint64 {
		return nil, errors.New("DSN generation overflow")
	}
	q.mu.Lock()
	if _, exists := q.accounted[id]; exists {
		q.mu.Unlock()
		return nil, fmt.Errorf("queue id %s is already ready", id)
	}
	meta, err := marshalEnvelope(env)
	if err != nil {
		q.mu.Unlock()
		return nil, err
	}
	physical := 2*disk.AllocationSize(int64(len(meta))+disk.AllocationSize(0)) + disk.AllocationSize(0)
	if err := q.reserveLocked(env.Size, physical, false, true); err != nil {
		q.mu.Unlock()
		return nil, err
	}
	q.mu.Unlock()
	held := true
	physicalHeld := physical
	defer func() {
		if held {
			q.releaseReserve(env.Size, physicalHeld)
		}
	}()

	for i := range env.Recipients {
		if env.Recipients[i].Status == StatusFailed {
			env.Recipients[i].Status = StatusPending
			env.Recipients[i].Detail = ""
			env.Recipients[i].Code = 0
			env.Recipients[i].EnhancedCode = ""
		}
	}
	env.Attempts = 0
	env.LastError = ""
	env.NextAttempt = time.Now()
	if env.DSNSourceID == "" {
		env.DSNGeneration++
		env.DSNID = ""
	}
	env.Revision = nextRevision
	if err := validateEnvelope(env); err != nil {
		return nil, err
	}

	stagedMeta := filepath.Join(src, reviveMetaName)
	if err := q.writeMeta(stagedMeta, env); err != nil {
		return nil, errors.Join(err, removeAndSync(stagedMeta))
	}
	// The staged metadata can survive every later error. Charge it immediately;
	// successful cleanup may leave a conservative overcount until reconciliation.
	q.mu.Lock()
	q.commitPhysicalLocked(physicalHeld)
	q.mu.Unlock()
	physicalHeld = 0
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

	q.finishMutation()
	mutationHeld = false
	q.mu.Lock()
	q.releaseReserveLocked(env.Size, physicalHeld)
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
	if err := q.beginOperation(); err != nil {
		return nil, err
	}
	defer q.endOperation()
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

// CorruptIDs lists quarantined entry names. Names are opaque and can be passed
// back to DeleteCorrupt.
func (q *Queue) CorruptIDs() ([]string, error) {
	if err := q.beginOperation(); err != nil {
		return nil, err
	}
	defer q.endOperation()
	entries, err := os.ReadDir(q.corr)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if validOpaqueName(entry.Name()) {
			ids = append(ids, entry.Name())
		}
	}
	return ids, nil
}

// DeleteDead crash-safely moves a dead letter through trash before deletion.
func (q *Queue) DeleteDead(id string) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	if err := q.beginTransition(id); err != nil {
		return err
	}
	defer q.endTransition(id)
	return q.deleteStored(q.dead, id, id)
}

// DeleteCorrupt crash-safely moves one opaque quarantine entry through trash.
func (q *Queue) DeleteCorrupt(name string) error {
	if !validOpaqueName(name) {
		return ErrInvalidID
	}
	return q.deleteStored(q.corr, name, "corrupt-"+sanitize(name))
}

func validOpaqueName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsAny(name, `/\`)
}

func (q *Queue) deleteStored(namespace, name, trashName string) error {
	if err := q.beginOperation(); err != nil {
		return err
	}
	defer q.endOperation()
	if err := q.rejectReadOnly(); err != nil {
		return err
	}
	if err := q.startMutation(); err != nil {
		return err
	}
	defer q.finishMutation()
	return q.deleteStoredLocked(namespace, name, trashName)
}

func (q *Queue) deleteStoredLocked(namespace, name, trashName string) error {
	src := filepath.Join(namespace, name)
	if _, err := os.Lstat(src); err != nil {
		return err
	}
	entryBytes, _ := disk.AllocatedBytes(src)
	dst := filepath.Join(q.trash, trashName+"."+strconv.FormatInt(time.Now().UnixNano(), 10))
	moved, err := moveState(src, dst)
	if err != nil && !moved {
		return err
	}
	if cleanupErr := q.removeTrash(dst); cleanupErr != nil {
		return errors.Join(err, fmt.Errorf("%w: %w", ErrCleanup, cleanupErr))
	}
	q.removePhysical(entryBytes)
	return err
}

// Prune crash-safely deletes dead and corrupt entries older than their
// configured retention. Zero retention disables that namespace.
func (q *Queue) Prune(now time.Time) (dead, corrupt int, err error) {
	if opErr := q.beginOperation(); opErr != nil {
		return 0, 0, opErr
	}
	defer q.endOperation()
	if opErr := q.rejectReadOnly(); opErr != nil {
		return 0, 0, opErr
	}
	if opErr := q.startMutation(); opErr != nil {
		return 0, 0, opErr
	}
	defer q.finishMutation()
	dead, deadErr := q.pruneNamespace(q.dead, q.limits.DeadRetention, now, "")
	corrupt, corruptErr := q.pruneNamespace(q.corr, q.limits.CorruptRetention, now, "corrupt-")
	return dead, corrupt, errors.Join(deadErr, corruptErr)
}

func (q *Queue) pruneNamespace(namespace string, retention time.Duration, now time.Time, prefix string) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	entries, err := os.ReadDir(namespace)
	if err != nil {
		return 0, err
	}
	var count int
	var errs []error
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			errs = append(errs, infoErr)
			continue
		}
		storedAt := info.ModTime()
		if namespace == q.corr {
			if dot := strings.LastIndexByte(entry.Name(), '.'); dot >= 0 {
				if stamp, parseErr := strconv.ParseInt(entry.Name()[dot+1:], 10, 64); parseErr == nil {
					storedAt = time.Unix(0, stamp)
				}
			}
		}
		if now.Sub(storedAt) < retention || !validOpaqueName(entry.Name()) {
			continue
		}
		if namespace == q.dead {
			q.mu.Lock()
			_, busy := q.transitioning[entry.Name()]
			q.mu.Unlock()
			if busy || ValidateID(entry.Name()) != nil {
				continue
			}
		}
		if deleteErr := q.deleteStoredLocked(namespace, entry.Name(), prefix+sanitize(entry.Name())); deleteErr != nil {
			errs = append(errs, fmt.Errorf("prune %s: %w", entry.Name(), deleteErr))
			continue
		}
		count++
	}
	return count, errors.Join(errs...)
}

// LoadDead reads a dead-letter envelope by id.
func (q *Queue) LoadDead(id string) (*Envelope, error) {
	if err := q.beginOperation(); err != nil {
		return nil, err
	}
	defer q.endOperation()
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	return q.loadAcceptedDir(filepath.Join(q.dead, id), id)
}

// ExportDead copies the original message to w.
func (q *Queue) ExportDead(id string, w io.Writer) error {
	if err := q.beginOperation(); err != nil {
		return err
	}
	defer q.endOperation()
	if err := ValidateID(id); err != nil {
		return err
	}
	dir := filepath.Join(q.dead, id)
	env, f, err := q.openAcceptedBody(dir, id)
	if err != nil {
		return err
	}
	defer f.Close()
	return copyExactBody(w, f, env.Size)
}

// Reader opens the stored message body for a ready entry.
func (q *Queue) Reader(id string) (io.ReadCloser, error) {
	if err := q.beginOperation(); err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			q.endOperation()
		}
	}()
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	dir := filepath.Join(q.ready, id)
	_, file, err := q.openAcceptedBody(dir, id)
	if err != nil {
		return nil, err
	}
	owned = false
	return &trackedReader{file: file, queue: q}, nil
}

// ReadBody returns the full body bytes for ready or dead.
func (q *Queue) ReadBody(id string) ([]byte, error) {
	if err := q.beginOperation(); err != nil {
		return nil, err
	}
	defer q.endOperation()
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	ready := filepath.Join(q.ready, id)
	if env, file, err := q.openAcceptedBody(ready, id); err == nil {
		defer file.Close()
		return readBodyFromFile(file, env.Size)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	dead := filepath.Join(q.dead, id)
	env, file, err := q.openAcceptedBody(dead, id)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBodyFromFile(file, env.Size)
}

// Path returns the spool root.
func (q *Queue) Path() string { return q.root }

// DeadDir returns the dead-letter directory.
func (q *Queue) DeadDir() string { return q.dead }

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
	heap.Push(&q.pending, cloneEnvelope(envelope))
	q.scheduled[envelope.ID] = struct{}{}
	return true
}

func cloneEnvelope(envelope *Envelope) *Envelope {
	clone := *envelope
	clone.Recipients = append([]Recipient(nil), envelope.Recipients...)
	clone.index = -1
	return &clone
}

func (q *Queue) noteAddedLocked(envelope *Envelope) bool {
	if _, exists := q.accounted[envelope.ID]; exists {
		return true
	}
	bytes, ok := checkedAddInt64(q.bytes, envelope.Size)
	if !ok || q.count == math.MaxInt {
		return false
	}
	q.accounted[envelope.ID] = accountedEntry{
		size:        envelope.Size,
		incarnation: envelope.Incarnation,
		revision:    envelope.Revision,
	}
	q.count++
	q.bytes = bytes
	return true
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
	nextRevision, err := incrementRevision(envelope.Revision)
	if err != nil {
		return err
	}
	dir := filepath.Join(q.ready, envelope.ID)
	if err := q.matchReady(envelope); err != nil {
		return err
	}
	path := filepath.Join(dir, metaName)
	updated := *envelope
	updated.Revision = nextRevision
	if err := validateEnvelope(&updated); err != nil {
		return err
	}
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
	state, err := readBoundedRegular(filepath.Join(dir, addStateName), maxAddStateBytes)
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
	body, err := marshalEnvelope(envelope)
	if err != nil {
		return err
	}
	return disk.Write(path, body, 0600)
}

func (q *Queue) writeMetaReconciled(path string, envelope *Envelope) (bool, error) {
	body, err := marshalEnvelope(envelope)
	if err != nil {
		return false, err
	}
	if err := disk.Write(path, body, 0600); err != nil {
		visible, readErr := readBoundedRegular(path, maxEnvelopeMetadata)
		if readErr == nil && bytes.Equal(visible, body) {
			return true, err
		}
		return false, errors.Join(err, readErr)
	}
	return true, nil
}

func (q *Queue) loadDir(dir, expectID string) (*Envelope, error) {
	env, err := loadEnvelopeMetadata(dir, expectID)
	if err != nil {
		return nil, err
	}
	file, info, err := openRegular(filepath.Join(dir, bodyName))
	if err != nil {
		return nil, fmt.Errorf("missing body: %w", err)
	}
	file.Close()
	if info.Size() != env.Size {
		return nil, fmt.Errorf("body size mismatch: metadata=%d actual=%d", env.Size, info.Size())
	}
	return env, nil
}

func loadEnvelopeMetadata(dir, expectID string) (*Envelope, error) {
	metaPath := filepath.Join(dir, metaName)

	raw, err := readBoundedRegular(metaPath, maxEnvelopeMetadata)
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
	return env, nil
}

func marshalEnvelope(envelope *Envelope) ([]byte, error) {
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if len(body) > maxEnvelopeMetadata {
		return nil, fmt.Errorf("envelope metadata exceeds %d bytes", maxEnvelopeMetadata)
	}
	return body, nil
}

func readBoundedRegular(path string, max int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("queue metadata is not a regular file")
	}
	if before.Size() > max {
		return nil, fmt.Errorf("queue metadata exceeds %d bytes", max)
	}
	file, _, err := openRegularFromInfo(path, before)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("queue metadata exceeds %d bytes", max)
	}
	return raw, nil
}

func openRegular(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	return openRegularFromInfo(path, before)
}

func openRegularFromInfo(path string, before os.FileInfo) (*os.File, os.FileInfo, error) {
	if !before.Mode().IsRegular() {
		return nil, nil, errors.New("queue file is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		file.Close()
		return nil, nil, errors.New("queue file changed while opening")
	}
	return file, after, nil
}

type trackedReader struct {
	file  *os.File
	queue *Queue
	once  sync.Once
	err   error
}

func (r *trackedReader) Read(p []byte) (int, error) {
	return r.file.Read(p)
}

func (r *trackedReader) Close() error {
	r.once.Do(func() {
		r.err = r.file.Close()
		r.queue.endOperation()
	})
	return r.err
}

func (q *Queue) openBody(path string, expected int64) (*os.File, error) {
	file, info, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	if info.Size() != expected {
		file.Close()
		return nil, fmt.Errorf("body size mismatch: metadata=%d actual=%d", expected, info.Size())
	}
	if q.afterBodyOpen != nil {
		q.afterBodyOpen()
	}
	info, err = file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != expected {
		file.Close()
		return nil, fmt.Errorf("body size mismatch: metadata=%d actual=%d", expected, info.Size())
	}
	return file, nil

}

func readBodyFromFile(file *os.File, expected int64) ([]byte, error) {
	var body bytes.Buffer
	if err := copyExactBody(&body, file, expected); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func copyExactBody(dst io.Writer, file *os.File, expected int64) error {
	limit, ok := checkedAddInt64(expected, 1)
	if !ok {
		return errors.New("body size is too large")
	}
	written, err := io.Copy(dst, io.LimitReader(file, limit))
	if err != nil {
		return err
	}
	if written != expected {
		return fmt.Errorf("body size mismatch while reading: metadata=%d actual=%d", expected, written)
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != expected {
		return fmt.Errorf("body size mismatch while reading: metadata=%d actual=%d", expected, info.Size())
	}
	return nil
}

// Open loads an existing spool directory, creating it when needed.
// Acquires an exclusive lock on <directory>/.lock before recovery or
// scheduling. Call Close to release it.
// Corrupt entries are relocated to corrupt/ and returned via Queue.Corrupt.
func Open(directory string, limits Limits) (*Queue, error) {
	if limits.MaxSpoolBytes < 0 || limits.SpoolEmergencyBytes < 0 || limits.MinFreeDisk < 0 || limits.DeadRetention < 0 || limits.CorruptRetention < 0 {
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
		scheduled:     make(map[string]struct{}),
		transitioning: make(map[string]struct{}),
		requeues:      make(map[string][]*Envelope),
		blocked:       make(map[string]struct{}),
		closeDone:     make(chan struct{}),
	}
	q.closeCond = sync.NewCond(&q.mu)
	if limits.MinFreeDisk > 0 {
		q.FreeDisk = disk.FreeBytes
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
	if err := q.refreshSpoolUsage(); err != nil {
		_ = q.Close()
		return nil, err
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
	if limits.DeadRetention > 0 || limits.CorruptRetention > 0 {
		dead, corrupt, pruneErr := q.Prune(time.Now())
		if pruneErr != nil {
			q.Warnings = append(q.Warnings, fmt.Errorf("startup prune: %w", pruneErr))
		} else if dead+corrupt > 0 {
			q.Warnings = append(q.Warnings, fmt.Errorf("startup prune removed %d dead and %d corrupt entries", dead, corrupt))
		}
	}
	if err := q.refreshSpoolUsage(); err != nil {
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
	q := &Queue{
		root:          directory,
		ready:         filepath.Join(directory, dirReady),
		dead:          filepath.Join(directory, dirDead),
		tmp:           filepath.Join(directory, dirTmp),
		dsn:           filepath.Join(directory, dirDSN),
		corr:          filepath.Join(directory, dirCorrupt),
		trash:         filepath.Join(directory, dirTrash),
		notify:        make(chan struct{}, 1),
		closeSignal:   make(chan struct{}),
		accounted:     make(map[string]accountedEntry),
		scheduled:     make(map[string]struct{}),
		transitioning: make(map[string]struct{}),
		requeues:      make(map[string][]*Envelope),
		blocked:       make(map[string]struct{}),
		closeDone:     make(chan struct{}),
		readOnly:      true,
	}
	q.closeCond = sync.NewCond(&q.mu)
	return q, nil
}

// Close releases the exclusive spool lock.
func (q *Queue) Close() error {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	if q.closing {
		done := q.closeDone
		q.mu.Unlock()
		<-done
		q.mu.Lock()
		err := q.closeErr
		q.mu.Unlock()
		return err
	}
	q.closing = true
	close(q.closeSignal)
	for q.active > 0 {
		q.closeCond.Wait()
	}
	lock := q.lock
	q.lock = nil
	q.mu.Unlock()

	var err error
	if lock != nil {
		err = lock.Close()
	}
	q.mu.Lock()
	q.closeErr = err
	close(q.closeDone)
	q.mu.Unlock()
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
			if err := os.Remove(filepath.Join(q.tmp, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				q.Warnings = append(q.Warnings, fmt.Errorf("remove stray tmp file %s: %w", e.Name(), err))
			}
			continue
		}
		id := e.Name()
		dir := filepath.Join(q.tmp, id)
		// tmp entries have not crossed Add's acceptance point. Completeness is
		// not evidence of acceptance, so preserve them only for diagnosis.
		if qerr := q.quarantineDir(dir, id+"-uncommitted"); qerr != nil {
			q.recordQuarantineFailure(id, dir, errors.New("interrupted uncommitted add"), qerr)
			continue
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
				q.recordQuarantineFailure(entry.Name(), path, errors.New("stray file in dsn"), err)
				continue
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("stray file in dsn: %s", entry.Name()))
			continue
		}
		id := entry.Name()
		if err := acceptedDir(path); err != nil {
			if qerr := q.quarantineDSNStage(path, id, "uncommitted", err); qerr != nil {
				q.recordQuarantineFailure(id, path, err, qerr)
			}
			continue
		}
		dsn, err := q.loadDir(path, id)
		if err != nil {
			if qerr := q.quarantineDSNStage(path, id, "invalid", err); qerr != nil {
				q.recordQuarantineFailure(id, path, err, qerr)
			}
			continue
		}
		source, err := q.loadDir(filepath.Join(q.ready, dsn.DSNSourceID), dsn.DSNSourceID)
		if err != nil || source.Incarnation != dsn.DSNSourceIncarnation || source.DSNID != dsn.ID || source.DSNGeneration != dsn.DSNGeneration {
			cause := errors.New("source link missing or invalid")
			if qerr := q.quarantineDSNStage(path, id, "orphan", cause); qerr != nil {
				q.recordQuarantineFailure(id, path, cause, qerr)
			}
			continue
		}
		readyDir := filepath.Join(q.ready, id)
		if _, err := os.Stat(readyDir); err == nil {
			existing, loadErr := q.loadDir(readyDir, id)
			if loadErr == nil && existing.Incarnation == dsn.Incarnation && existing.DSNSourceID == dsn.DSNSourceID && existing.DSNSourceIncarnation == dsn.DSNSourceIncarnation && existing.DSNGeneration == dsn.DSNGeneration {
				if err := q.quarantineDir(path, id+"-dsn-duplicate"); err != nil {
					q.recordQuarantineFailure(id, path, errors.New("duplicate ready DSN"), err)
					continue
				}
				q.Corrupt = append(q.Corrupt, fmt.Errorf("staged DSN %s: duplicate ready entry", id))
				continue
			}
			cause := fmt.Errorf("%w: ready DSN collision", ErrIDConflict)
			if err := q.quarantineDSNStage(path, id, "collision", cause); err != nil {
				q.recordQuarantineFailure(id, path, cause, err)
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			q.recordBlocked(id, path, fmt.Errorf("inspect ready DSN: %w", err))
			q.recordBlocked(source.ID, filepath.Join(q.ready, source.ID), fmt.Errorf("linked DSN %s could not be inspected", id))
			continue
		}
		moved, err := moveState(path, readyDir)
		if err != nil {
			q.recordBlocked(id, path, fmt.Errorf("publish recovered DSN (moved=%t): %w", moved, err))
			q.recordBlocked(source.ID, filepath.Join(q.ready, source.ID), fmt.Errorf("linked DSN %s publication is unresolved", id))
			continue
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
		raw, err := readBoundedRegular(filepath.Join(sourceDir, metaName), maxEnvelopeMetadata)
		if err != nil {
			continue
		}
		var source Envelope
		if json.Unmarshal(raw, &source) != nil || source.DSNID != id {
			continue
		}
		if err := q.quarantineDir(sourceDir, source.ID+"-dsn-source"); err != nil {
			q.recordQuarantineFailure(source.ID, sourceDir, fmt.Errorf("linked staged DSN %s is invalid", id), err)
			continue
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
		if _, blocked := q.blocked[e.Name()]; blocked {
			continue
		}
		if !e.IsDir() {
			// stray file
			if err := q.quarantineFile(filepath.Join(q.ready, e.Name()), e.Name()+"-stray"); err != nil {
				q.recordQuarantineFailure(e.Name(), filepath.Join(q.ready, e.Name()), errors.New("stray file in ready"), err)
				continue
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("stray file in ready: %s", e.Name()))
			continue
		}
		id := e.Name()
		dir := filepath.Join(q.ready, id)
		if err := ValidateID(id); err != nil {
			if qerr := q.quarantineDir(dir, "badid-"+sanitize(id)); qerr != nil {
				q.recordQuarantineFailure(id, dir, err, qerr)
				continue
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: %w", id, err))
			continue
		}
		state, err := readBoundedRegular(filepath.Join(dir, addStateName), maxAddStateBytes)
		if err != nil {
			if qerr := q.quarantineDir(dir, id); qerr != nil {
				q.recordQuarantineFailure(id, dir, fmt.Errorf("read add state: %w", err), qerr)
				continue
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: read add state: %w", id, err))
			continue
		}
		if string(state) != addAccepted {
			if qerr := q.quarantineDir(dir, id+"-uncommitted"); qerr != nil {
				q.recordQuarantineFailure(id, dir, errors.New("uncommitted or invalid add state"), qerr)
				continue
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: uncommitted or invalid add state", id))
			continue
		}
		stagedMeta := filepath.Join(dir, reviveMetaName)
		if _, err := os.Stat(stagedMeta); err == nil {
			moved, moveErr := moveState(stagedMeta, filepath.Join(dir, metaName))
			if moveErr != nil && !moved {
				q.recordBlocked(id, dir, fmt.Errorf("complete revive: %w", moveErr))
				continue
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			q.recordBlocked(id, dir, fmt.Errorf("inspect revive: %w", err))
			continue
		}
		env, err := q.loadDir(dir, id)
		if err != nil {
			if qerr := q.quarantineDir(dir, id); qerr != nil {
				q.recordQuarantineFailure(id, dir, err, qerr)
				continue
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: %w", id, err))
			continue
		}
		deadDir := filepath.Join(q.dead, id)
		dead, deadErr := q.loadAcceptedDir(deadDir, id)
		if deadErr == nil {
			if dead.Incarnation != env.Incarnation || dead.Revision != env.Revision {
				q.recordBlocked(id, dir, fmt.Errorf("%w: ready and dead entries differ", ErrIDConflict))
				continue
			}
			if qerr := q.quarantineDir(dir, id+"-dead-duplicate"); qerr != nil {
				q.recordQuarantineFailure(id, dir, errors.New("duplicate dead-letter entry"), qerr)
				continue
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: duplicate dead-letter entry", id))
			continue
		}
		if !errors.Is(deadErr, os.ErrNotExist) {
			if qerr := q.quarantineDir(deadDir, id+"-invalid-dead"); qerr != nil {
				q.recordQuarantineFailure(id, deadDir, deadErr, qerr)
				continue
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("dead %s: %w", id, deadErr))
		}
		if !q.noteAddedLocked(env) {
			if qerr := q.quarantineDir(dir, id+"-accounting-overflow"); qerr != nil {
				q.recordQuarantineFailure(id, dir, errors.New("queue accounting overflow"), qerr)
				continue
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: queue accounting overflow", id))
			continue
		}
		q.scheduleLocked(env)
	}
	return nil
}

func (q *Queue) recordQuarantineFailure(id, path string, cause, quarantineErr error) {
	q.blocked[id] = struct{}{}
	q.Corrupt = append(q.Corrupt, fmt.Errorf("QUARANTINE FAILED; BLOCKED %s at %s: %v (relocation: %w)", id, path, cause, quarantineErr))
}

func (q *Queue) recordBlocked(id, path string, cause error) {
	q.blocked[id] = struct{}{}
	q.Corrupt = append(q.Corrupt, fmt.Errorf("BLOCKED %s at %s: %w", id, path, cause))
}

func (q *Queue) loadAcceptedDir(dir, expectID string) (*Envelope, error) {
	env, err := loadAcceptedMetadata(dir, expectID)
	if err != nil {
		return nil, err
	}
	file, info, err := openRegular(filepath.Join(dir, bodyName))
	if err != nil {
		return nil, fmt.Errorf("missing body: %w", err)
	}
	file.Close()
	if info.Size() != env.Size {
		return nil, fmt.Errorf("body size mismatch: metadata=%d actual=%d", env.Size, info.Size())
	}
	return env, nil
}

func loadAcceptedMetadata(dir, expectID string) (*Envelope, error) {
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
	return loadEnvelopeMetadata(dir, expectID)
}

func (q *Queue) openAcceptedBody(dir, expectID string) (*Envelope, *os.File, error) {
	env, err := loadAcceptedMetadata(dir, expectID)
	if err != nil {
		return nil, nil, err
	}
	file, err := q.openBody(filepath.Join(dir, bodyName), env.Size)
	if err != nil {
		return nil, nil, err
	}
	return env, file, nil
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
	if err := disk.Rename(src, dst); err != nil {
		_ = os.Remove(dstDir)
		return fmt.Errorf("quarantine file %s: %w", src, err)
	}
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
	if e.Revision == 0 || e.Revision > maxEnvelopeRevision {
		return errors.New("invalid queue revision")
	}
	if e.Username == "" {
		return errors.New("missing username")
	}
	if len(e.Username) > maxEnvelopeStringBytes {
		return errors.New("username too long")
	}
	if len(e.LastError) > maxEnvelopeDetailBytes {
		return errors.New("last error too long")
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
	if len(e.Recipients) > maxEnvelopeRecipients {
		return fmt.Errorf("too many recipients: maximum is %d", maxEnvelopeRecipients)
	}
	if e.Created.IsZero() {
		return errors.New("missing created timestamp")
	}
	if e.Attempts < 0 || e.Attempts > maxEnvelopeAttempts {
		return errors.New("invalid attempts")
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
		if len(r.Domain) > maxEnvelopeStringBytes {
			return fmt.Errorf("recipient[%d]: domain too long", i)
		}
		if len(r.Detail) > maxEnvelopeDetailBytes {
			return fmt.Errorf("recipient[%d]: detail too long", i)
		}
		if containsDisplayControl(r.Detail) {
			return fmt.Errorf("recipient[%d]: detail contains display control characters", i)
		}
		switch r.Status {
		case "":
			r.Status = StatusPending
		case StatusPending, StatusSent, StatusFailed:
		default:
			return fmt.Errorf("recipient[%d]: invalid status %q", i, r.Status)
		}
		if r.Code != 0 && (r.Code < 200 || r.Code > 599) {
			return fmt.Errorf("recipient[%d]: invalid SMTP code", i)
		}
		if r.EnhancedCode != "" && (r.Code == 0 || !validEnhancedCode(r.EnhancedCode, r.Code)) {
			return fmt.Errorf("recipient[%d]: invalid enhanced SMTP code", i)
		}
		switch r.Status {
		case StatusPending:
			if r.Code != 0 || r.EnhancedCode != "" {
				return fmt.Errorf("recipient[%d]: pending recipient has a terminal SMTP code", i)
			}
		case StatusSent:
			if r.Code != 0 && r.Code/100 != 2 {
				return fmt.Errorf("recipient[%d]: sent recipient has a non-success SMTP code", i)
			}
		case StatusFailed:
			if r.Code != 0 && r.Code/100 != 5 {
				return fmt.Errorf("recipient[%d]: failed recipient has a non-permanent SMTP code", i)
			}
		}
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
	}
	// Non-ASCII envelope addresses require the SMTPUTF8 flag so outbound MAIL/RCPT
	// never emit UTF-8 without the SMTPUTF8 MAIL parameter. ASCII envelopes may set
	// the flag when headers independently require it; the flag is never cleared here.
	if needUTF8 && !e.SMTPUTF8 {
		return errors.New("SMTPUTF8 required for non-ASCII envelope address")
	}
	if !envelopeMetadataWithinLimit(e) {
		return fmt.Errorf("envelope metadata exceeds %d bytes", maxEnvelopeMetadata)
	}
	return nil
}

func containsDisplayControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return true
		}
	}
	return false
}

func incrementRevision(revision uint64) (uint64, error) {
	if revision == 0 || revision >= maxEnvelopeRevision {
		return 0, errors.New("queue revision cannot be incremented")
	}
	return revision + 1, nil
}

func envelopeMetadataWithinLimit(e *Envelope) bool {
	// JSON can expand a byte to a six-byte escape. Include ample fixed overhead
	// per envelope and recipient so validation rejects before marshaling.
	remaining := int64(maxEnvelopeMetadata) - 2048 - int64(len(e.Recipients))*256
	strings := []string{
		e.ID, e.Incarnation, e.Username, e.Sender, e.LastError, e.DSNID,
		e.DSNSourceID, e.DSNSourceIncarnation,
	}
	for i := range e.Recipients {
		strings = append(strings, e.Recipients[i].Address, e.Recipients[i].Domain, string(e.Recipients[i].Status), e.Recipients[i].Detail, e.Recipients[i].EnhancedCode)
	}
	for _, value := range strings {
		if int64(len(value)) > remaining/6 {
			return false
		}
		remaining -= int64(len(value)) * 6
	}
	return remaining >= 0
}

func validEnhancedCode(enhanced string, code int) bool {
	parts := strings.Split(enhanced, ".")
	if len(parts) != 3 || len(parts[0]) != 1 || (parts[0] != "2" && parts[0] != "4" && parts[0] != "5") {
		return false
	}
	if code != 0 && int(parts[0][0]-'0') != code/100 {
		return false
	}
	for _, part := range parts[1:] {
		if len(part) < 1 || len(part) > 3 {
			return false
		}
		for i := range len(part) {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
		}
	}
	return true
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
	if len(addr) > maxEnvelopeStringBytes {
		return errors.New("address too long")
	}
	for i := 0; i < len(addr); i++ {
		if addr[i] < 0x20 || addr[i] == 0x7f {
			return errors.New("control character in address")
		}
	}
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return errors.New("missing @domain")
	}
	if strings.Contains(addr, " ") {
		return errors.New("whitespace in address")
	}
	return nil
}
