package queue

import (
	"errors"
	"math"

	"github.com/coalaura/outboxd/internal/disk"
)

// MinimumSpoolEmergencyBytes guarantees room for one bounded DSN transaction,
// source metadata replacement, and a terminal namespace transition.
const MinimumSpoolEmergencyBytes int64 = 16 << 20

// PhysicalStats describes the conservative spool admission estimate,
// including active reservations. It is intentionally not physical disk usage.
// HighWater is true once ordinary writes are in emergency headroom or the hard
// limit is at least 90 percent consumed.
type PhysicalStats struct {
	Used      int64
	Reserved  int64
	Limit     int64
	Emergency int64
	HighWater bool
}

var terminalSpoolReserve = disk.AllocationSize(maxEnvelopeMetadata+disk.AllocationSize(0)) + disk.AllocationSize(0)

// SpoolStats returns the conservative application admission estimate across
// ready, tmp, dsn, dead, corrupt, and trash, including concurrent reservations.
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

func (q *Queue) holdPhysical(bytes int64, terminal bool) (func(bool), error) {
	q.mu.Lock()
	err := q.reservePhysicalLocked(bytes, true, terminal)
	q.mu.Unlock()

	if err != nil {
		return nil, err
	}

	return func(commit bool) {
		q.mu.Lock()
		if commit {
			q.commitPhysicalLocked(bytes)
		} else if bytes > q.spoolReserved {
			q.spoolReserved = 0
		} else {
			q.spoolReserved -= bytes
		}
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

func (q *Queue) adjustPhysicalDelta(before, after int64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if after >= before {
		q.addPhysicalLocked(after - before)

		return
	}

	delta := before - after
	if delta >= q.spoolBytes {
		q.spoolBytes = 0
	} else {
		q.spoolBytes -= delta
	}
}

func (q *Queue) reservePhysicalLocked(physical int64, emergency, terminal bool) error {
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
		} else if !terminal {
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
		} else if !terminal {
			floor, ok = checkedAddInt64(floor, terminalSpoolReserve)
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

func estimateEntryAllocation(bodySize int64, metadataSize int) int64 {
	parts := []int64{
		estimatePersistentEntryAllocation(bodySize, metadataSize),
		// The staging namespace may cross an allocation boundary while the
		// entry is moved into ready/.
		disk.AllocationSize(0),
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

func estimatePersistentEntryAllocation(bodySize int64, metadataSize int) int64 {
	parts := []int64{
		disk.AllocationSize(0),
		disk.AllocationSize(bodySize),
		disk.AllocationSize(int64(metadataSize)),
		disk.AllocationSize(int64(len(addAccepted))),
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
