package queue

import (
	"errors"
	"math"
	"time"
)

// Limits caps the durable queue. MaxBytes is the logical size of message
// bodies in ready/. MaxSpoolBytes is a conservative application admission
// limit across every queue namespace, not a physical disk-usage measurement.
// Zero means unlimited for that dimension.
type Limits struct {
	MaxMessages         int
	MaxBytes            int64
	MaxMessagesPerUser  int
	MaxBytesPerUser     int64
	MaxSpoolBytes       int64
	SpoolEmergencyBytes int64
	MinFreeDisk         int64
	DeadRetention       time.Duration
	CorruptRetention    time.Duration
}

type accountedEntry struct {
	size        int64
	owner       string
	incarnation string
	revision    uint64
}

type userUsage struct {
	messages int
	bytes    int64
	reserved int
	resBytes int64
}

// reserveLocked checks logical and conservative spool admission quotas.
// Emergency operations may consume the configured reserve but never the hard
// admission limit or free-space floor.
func (q *Queue) reserveLocked(size, physical int64, exempt, emergency bool, owner string) error {
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

		usage := q.users[owner]

		userMessages, ok := checkedAddInt(usage.messages, usage.reserved)
		if !ok || (q.limits.MaxMessagesPerUser > 0 && userMessages >= q.limits.MaxMessagesPerUser) {
			return ErrQueueFull
		}

		userBytes, ok := checkedAddInt64(usage.bytes, usage.resBytes)
		if !ok {
			return ErrQueueFull
		}

		userBytes, ok = checkedAddInt64(userBytes, size)
		if !ok || (q.limits.MaxBytesPerUser > 0 && userBytes > q.limits.MaxBytesPerUser) {
			return ErrQueueFull
		}
	}

	err := q.reservePhysicalLocked(physical, emergency, false)
	if err != nil {
		return err
	}

	q.reserved++
	q.resBytes = reservedBytes

	if !exempt {
		usage := q.users[owner]

		usage.reserved++
		usage.resBytes += size

		q.users[owner] = usage
	}

	return nil
}

func (q *Queue) releaseReserveLocked(size, physical int64, owner string) {
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

	if owner != "" {
		usage := q.users[owner]
		if usage.reserved > 0 {
			usage.reserved--
		}

		if size >= usage.resBytes {
			usage.resBytes = 0
		} else {
			usage.resBytes -= size
		}

		q.users[owner] = usage
	}
}

func (q *Queue) releaseReserve(size, physical int64, owner string) {
	q.mu.Lock()
	q.releaseReserveLocked(size, physical, owner)
	q.mu.Unlock()
}

func (q *Queue) noteAddedLocked(envelope *Envelope) bool {
	_, exists := q.accounted[envelope.ID]
	if exists {
		return true
	}

	bytes, ok := checkedAddInt64(q.bytes, envelope.Size)
	if !ok || q.count == math.MaxInt {
		return false
	}

	q.accounted[envelope.ID] = accountedEntry{
		size:        envelope.Size,
		owner:       quotaOwner(envelope),
		incarnation: envelope.Incarnation,
		revision:    envelope.Revision,
	}

	q.count++
	q.bytes = bytes

	owner := quotaOwner(envelope)
	if owner != "" {
		usage := q.users[owner]

		usage.messages++
		usage.bytes += envelope.Size

		q.users[owner] = usage
	}

	return true
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

		if entry.owner != "" {
			usage := q.users[entry.owner]

			usage.messages--
			usage.bytes -= entry.size

			if usage.messages == 0 && usage.reserved == 0 {
				delete(q.users, entry.owner)
			} else {
				q.users[entry.owner] = usage
			}
		}
	}

	q.mu.Unlock()
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

func quotaOwner(envelope *Envelope) string {
	if envelope.DSNSourceID != "" {
		return ""
	}

	return envelope.Username
}
