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
//	  ready/<id>/        # durable, eligible for delivery
//	    meta.json
//	    message.eml
//	  dead/<id>/         # permanent failure / exhausted
//	  corrupt/<id>/      # quarantined unreadable entries
//
// Queue.Add builds under tmp/ and renames into ready/. Finish moves ready →
// trash rename-delete. Bury moves ready → dead. Corrupt entries are moved to
// corrupt/ with a logged error; they are never silently deleted.
//
// Legacy flat <id>.json + <id>.eml pairs are migrated into ready/<id>/ on Open.
package queue

import (
	"container/heap"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coalaura/outboxd/internal/disk"
)

// Status is the delivery state of a single recipient.
type Status string

const (
	StatusPending Status = "pending"
	StatusSent    Status = "sent"
	StatusFailed  Status = "failed"
)

const (
	metaName = "meta.json"
	bodyName = "message.eml"

	dirReady   = "ready"
	dirDead    = "dead"
	dirTmp     = "tmp"
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
	// DSNSent is set once a failure DSN has been durably queued, making DSN
	// generation crash-idempotent.
	DSNSent bool `json:"dsn_sent,omitempty"`
	// IsDSN marks this envelope as a delivery-status notification so a
	// permanent failure must not produce another DSN.
	IsDSN bool `json:"is_dsn,omitempty"`
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

// Queue is a durable, crash-safe spool of messages awaiting delivery.
type Queue struct {
	root  string
	ready string
	dead  string
	tmp   string
	corr  string
	trash string

	limits Limits

	// FreeDisk is optional; when set, Add consults it for MinFreeDisk.
	FreeDisk func(path string) (int64, error)

	mu       sync.Mutex
	pending  schedule
	notify   chan struct{}
	count    int
	bytes    int64
	reserved int   // in-flight Add reservations (count)
	resBytes int64 // in-flight Add reservations (bytes)

	// Corrupt holds reportable quarantine events from Open.
	Corrupt []error
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
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.reserveLocked(size)
}

func (q *Queue) reserveLocked(size int64) error {
	if q.limits.MaxMessages > 0 && q.count+q.reserved+1 > q.limits.MaxMessages {
		return ErrQueueFull
	}
	if q.limits.MaxBytes > 0 && q.bytes+q.resBytes+size > q.limits.MaxBytes {
		return ErrQueueFull
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
)

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

// Add durably stores a message and schedules it for immediate delivery.
// On success the entry is complete under ready/; a crash mid-add leaves either
// nothing visible to Next, or a tmp/ entry recovered on restart.
func (q *Queue) Add(envelope *Envelope, data []byte) error {
	if err := ValidateID(envelope.ID); err != nil {
		return err
	}
	envelope.Size = int64(len(data))
	if err := validateEnvelope(envelope); err != nil {
		return err
	}

	// Capacity check accounts for concurrent in-progress connections via reserved.
	q.mu.Lock()
	if err := q.reserveLocked(envelope.Size); err != nil {
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

	readyDir := filepath.Join(q.ready, envelope.ID)
	if err := disk.Rename(tmpDir, readyDir); err != nil {
		return err
	}
	if err := disk.Sync(q.ready); err != nil {
		return err
	}

	success = true
	held = false

	q.mu.Lock()
	q.releaseReserveLocked(envelope.Size)
	q.count++
	q.bytes += envelope.Size
	heap.Push(&q.pending, envelope)
	q.mu.Unlock()

	q.signal()
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
	q.schedule(envelope)
}

// Retry persists the updated envelope and reschedules it.
// On persistence failure the envelope is NOT removed from recoverability:
// it remains under ready/ and is returned to the schedule so a subsequent
// Open recovers it. The error is returned to the caller.
func (q *Queue) Retry(envelope *Envelope) error {
	if err := ValidateID(envelope.ID); err != nil {
		return err
	}
	if err := validateEnvelope(envelope); err != nil {
		// Still reschedule so we do not strand.
		q.schedule(envelope)
		return err
	}
	if err := q.storeReady(envelope); err != nil {
		// Leave bytes on disk; put leaveit schedulable.
		q.schedule(envelope)
		return err
	}
	q.schedule(envelope)
	return nil
}

// Finish removes a fully handled message from the spool. Crash-safe: the
// directory is renamed into trash/ then removed. A crash after rename leaves
// a trash entry cleaned on Open.
func (q *Queue) Finish(envelope *Envelope) error {
	if err := ValidateID(envelope.ID); err != nil {
		return err
	}
	src := filepath.Join(q.ready, envelope.ID)
	dst := filepath.Join(q.trash, envelope.ID+"."+fmt.Sprintf("%d", time.Now().UnixNano()))
	if err := disk.Mkdir(q.trash); err != nil {
		return err
	}
	if err := disk.Rename(src, dst); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Already gone — treat as success for idempotence.
			q.noteRemoved(envelope.Size)
			return nil
		}
		return err
	}
	_ = os.RemoveAll(dst)
	_ = disk.Sync(q.trash)
	_ = disk.Sync(q.ready)
	q.noteRemoved(envelope.Size)
	return nil
}

// Bury moves an undeliverable message into the dead-letter directory atomically
// (single directory rename). Metadata is written first inside ready/.
func (q *Queue) Bury(envelope *Envelope) error {
	if err := ValidateID(envelope.ID); err != nil {
		return err
	}
	if err := validateEnvelope(envelope); err != nil {
		return err
	}
	// Persist final status inside ready/ before the rename.
	if err := q.storeReady(envelope); err != nil {
		// Reschedule for recoverability; signal fatal to caller.
		q.schedule(envelope)
		return err
	}
	src := filepath.Join(q.ready, envelope.ID)
	dst := filepath.Join(q.dead, envelope.ID)
	// If a previous bury partially created dst, refuse to clobber blindly —
	// move aside.
	if _, err := os.Stat(dst); err == nil {
		backup := dst + ".bak." + fmt.Sprintf("%d", time.Now().UnixNano())
		if err := disk.Rename(dst, backup); err != nil {
			q.schedule(envelope)
			return err
		}
	}
	if err := disk.Rename(src, dst); err != nil {
		q.schedule(envelope)
		return err
	}
	_ = disk.Sync(q.dead)
	_ = disk.Sync(q.ready)
	q.noteRemoved(envelope.Size)
	return nil
}

// ReviveDead moves a dead-letter item back to ready and schedules it.
func (q *Queue) ReviveDead(id string) (*Envelope, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	src := filepath.Join(q.dead, id)
	env, err := q.loadDir(src, id)
	if err != nil {
		return nil, err
	}
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
	env.DSNSent = false

	if err := q.writeMeta(filepath.Join(src, metaName), env); err != nil {
		return nil, err
	}
	dst := filepath.Join(q.ready, id)
	if err := disk.Rename(src, dst); err != nil {
		return nil, err
	}
	_ = disk.Sync(q.ready)
	_ = disk.Sync(q.dead)

	q.mu.Lock()
	q.count++
	q.bytes += env.Size
	heap.Push(&q.pending, env)
	q.mu.Unlock()
	q.signal()
	return env, nil
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
	return q.loadDir(filepath.Join(q.dead, id), id)
}

// ExportDead copies the original message to w.
func (q *Queue) ExportDead(id string, w io.Writer) error {
	if err := ValidateID(id); err != nil {
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
	return os.OpenFile(filepath.Join(q.ready, id, bodyName), os.O_RDONLY, 0)
}

// ReadBody returns the full body bytes for ready or dead.
func (q *Queue) ReadBody(id string) ([]byte, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	path := filepath.Join(q.ready, id, bodyName)
	body, err := os.ReadFile(path)
	if err == nil {
		return body, nil
	}
	return os.ReadFile(filepath.Join(q.dead, id, bodyName))
}

// Path returns the spool root.
func (q *Queue) Path() string { return q.root }

// DeadDir returns the dead-letter directory.
func (q *Queue) DeadDir() string { return q.dead }

func (q *Queue) schedule(envelope *Envelope) {
	q.mu.Lock()
	heap.Push(&q.pending, envelope)
	q.mu.Unlock()
	q.signal()
}

func (q *Queue) signal() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *Queue) noteRemoved(size int64) {
	q.mu.Lock()
	if q.count > 0 {
		q.count--
	}
	q.bytes -= size
	if q.bytes < 0 {
		q.bytes = 0
	}
	q.mu.Unlock()
}

func (q *Queue) storeReady(envelope *Envelope) error {
	path := filepath.Join(q.ready, envelope.ID, metaName)
	return q.writeMeta(path, envelope)
}

func (q *Queue) writeMeta(path string, envelope *Envelope) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return disk.Write(path, body, 0600)
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
	st, err := os.Stat(bodyPath)
	if err != nil {
		return nil, fmt.Errorf("missing body: %w", err)
	}
	if env.Size == 0 {
		env.Size = st.Size()
	}
	return env, nil
}

// Open loads an existing spool directory, creating it when needed.
// Corrupt entries are relocated to corrupt/ and returned via Queue.Corrupt.
func Open(directory string, limits Limits) (*Queue, error) {
	q := &Queue{
		root:   directory,
		ready:  filepath.Join(directory, dirReady),
		dead:   filepath.Join(directory, dirDead),
		tmp:    filepath.Join(directory, dirTmp),
		corr:   filepath.Join(directory, dirCorrupt),
		trash:  filepath.Join(directory, dirTrash),
		limits: limits,
		notify: make(chan struct{}, 1),
	}

	for _, d := range []string{q.root, q.ready, q.dead, q.tmp, q.corr, q.trash} {
		if err := disk.Mkdir(d); err != nil {
			return nil, err
		}
	}

	if err := q.migrateLegacy(); err != nil {
		return nil, err
	}
	if err := q.recoverTmp(); err != nil {
		return nil, err
	}
	if err := q.cleanTrash(); err != nil {
		return nil, err
	}
	if err := q.loadReady(); err != nil {
		return nil, err
	}
	return q, nil
}

// OpenDefault is Open with unlimited quotas (backward compatible helper).
func OpenDefault(directory string) (*Queue, error) {
	return Open(directory, Limits{})
}

func (q *Queue) migrateLegacy() error {
	entries, err := os.ReadDir(q.root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if err := ValidateID(id); err != nil {
			if moveErr := q.quarantineFile(filepath.Join(q.root, name), id+"-meta"); moveErr != nil {
				return moveErr
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("legacy metadata %s: invalid id: %w", name, err))
			continue
		}
		metaPath := filepath.Join(q.root, name)
		bodyPath := filepath.Join(q.root, id+".eml")
		if _, err := os.Stat(bodyPath); err != nil {
			if moveErr := q.quarantineFile(metaPath, id+"-meta-orphan"); moveErr != nil {
				return moveErr
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("legacy metadata %s without body", name))
			continue
		}
		// Build temp dir and rename into ready.
		env, err := readLegacy(metaPath)
		if err != nil {
			_ = q.quarantineFile(metaPath, id+"-meta-bad")
			_ = q.quarantineFile(bodyPath, id+"-body-bad")
			q.Corrupt = append(q.Corrupt, fmt.Errorf("legacy %s: %w", id, err))
			continue
		}
		if env.ID != id {
			_ = q.quarantineFile(metaPath, id+"-meta-mismatch")
			_ = q.quarantineFile(bodyPath, id+"-body-mismatch")
			q.Corrupt = append(q.Corrupt, fmt.Errorf("legacy %s: id mismatch %q", id, env.ID))
			continue
		}
		tmpDir := filepath.Join(q.tmp, id)
		_ = os.RemoveAll(tmpDir)
		if err := disk.Mkdir(tmpDir); err != nil {
			return err
		}
		body, err := os.ReadFile(bodyPath)
		if err != nil {
			return err
		}
		if err := disk.Write(filepath.Join(tmpDir, bodyName), body, 0600); err != nil {
			return err
		}
		meta, _ := json.Marshal(env)
		if err := disk.Write(filepath.Join(tmpDir, metaName), meta, 0600); err != nil {
			return err
		}
		if err := disk.Sync(tmpDir); err != nil {
			return err
		}
		if err := disk.Rename(tmpDir, filepath.Join(q.ready, id)); err != nil {
			return err
		}
		_ = os.Remove(metaPath)
		_ = os.Remove(bodyPath)
	}

	// Orphan legacy bodies without metadata.
	entries, err = os.ReadDir(q.root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".eml") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".eml")
		if err := q.quarantineFile(filepath.Join(q.root, e.Name()), id+"-body-orphan"); err != nil {
			return err
		}
		q.Corrupt = append(q.Corrupt, fmt.Errorf("legacy body %s without metadata", e.Name()))
	}
	return nil
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
		// Complete the add only if both files exist and validate.
		env, err := q.loadDir(dir, id)
		if err != nil {
			if qerr := q.quarantineDir(dir, id); qerr != nil {
				return qerr
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("tmp %s incomplete: %w", id, err))
			continue
		}
		// Promote to ready — durable completion after crash mid-rename.
		dst := filepath.Join(q.ready, id)
		if _, err := os.Stat(dst); err == nil {
			// ready already has it; drop tmp
			_ = os.RemoveAll(dir)
			continue
		}
		if err := disk.Rename(dir, dst); err != nil {
			return err
		}
		_ = env // scheduled in loadReady
	}
	return disk.Sync(q.tmp)
}

func (q *Queue) cleanTrash() error {
	entries, err := os.ReadDir(q.trash)
	if err != nil {
		return err
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(q.trash, e.Name()))
	}
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
		env, err := q.loadDir(dir, id)
		if err != nil {
			if qerr := q.quarantineDir(dir, id); qerr != nil {
				return qerr
			}
			q.Corrupt = append(q.Corrupt, fmt.Errorf("ready %s: %w", id, err))
			continue
		}
		q.count++
		q.bytes += env.Size
		heap.Push(&q.pending, env)
	}
	return nil
}

func (q *Queue) quarantineDir(src, name string) error {
	if err := disk.Mkdir(q.corr); err != nil {
		return err
	}
	dst := filepath.Join(q.corr, name+"."+fmt.Sprintf("%d", time.Now().UnixNano()))
	if err := disk.Rename(src, dst); err != nil {
		// fallback copy-ish remove
		return fmt.Errorf("quarantine %s: %w", src, err)
	}
	_ = disk.Sync(q.corr)
	return nil
}

func (q *Queue) quarantineFile(src, name string) error {
	if err := disk.Mkdir(q.corr); err != nil {
		return err
	}
	dstDir := filepath.Join(q.corr, name+"."+fmt.Sprintf("%d", time.Now().UnixNano()))
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

func readLegacy(path string) (*Envelope, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	env := new(Envelope)
	if err := json.Unmarshal(body, env); err != nil {
		return nil, err
	}
	if err := validateEnvelope(env); err != nil {
		return nil, err
	}
	return env, nil
}

func validateEnvelope(e *Envelope) error {
	if err := ValidateID(e.ID); err != nil {
		return err
	}
	if e.Username == "" {
		return errors.New("missing username")
	}
	// Null sender is allowed for DSNs.
	if e.Sender != "" {
		if err := validateAddress(e.Sender); err != nil {
			return fmt.Errorf("sender: %w", err)
		}
	} else if !e.IsDSN {
		return errors.New("missing sender")
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
	for i := range e.Recipients {
		r := &e.Recipients[i]
		if err := validateAddress(r.Address); err != nil {
			return fmt.Errorf("recipient[%d]: %w", i, err)
		}
		domain := r.Address[strings.LastIndexByte(r.Address, '@')+1:]
		if r.Domain == "" {
			r.Domain = strings.ToLower(domain)
		} else if !strings.EqualFold(r.Domain, domain) {
			return fmt.Errorf("recipient[%d]: domain mismatch", i)
		}
		r.Domain = strings.ToLower(r.Domain)
		switch r.Status {
		case StatusPending, StatusSent, StatusFailed:
		case "":
			r.Status = StatusPending
		default:
			return fmt.Errorf("recipient[%d]: invalid status %q", i, r.Status)
		}
	}
	return nil
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
