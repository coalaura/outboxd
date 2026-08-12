package queue

import (
	"errors"
	"fmt"
	"syscall"
)

type acceptanceUnknownError struct {
	cause error
}

var (
	// ErrQueueFull is returned when message count or byte quotas are exhausted.
	ErrQueueFull = errors.New("queue full")

	// ErrInsufficientDisk is returned when free disk is below the threshold.
	ErrInsufficientDisk = errors.New("insufficient free disk space")

	// ErrSpoolFull is returned when the conservative spool admission limit is exhausted.
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

	// ErrCorrupt identifies deterministic durable-integrity violations. Transient
	// filesystem errors are deliberately not wrapped with this sentinel.
	ErrCorrupt = errors.New("queue entry corrupt")

	// ErrAcceptanceUnknown means Add could not prove whether an accepted entry
	// can survive recovery. Callers must not blindly resubmit the message.
	ErrAcceptanceUnknown = errors.New("queue acceptance outcome unknown")

	errNilEnvelope = errors.New("nil envelope")
)

func (e *acceptanceUnknownError) Error() string {
	return fmt.Sprintf("%v: %v", ErrAcceptanceUnknown, e.cause)
}

func (e *acceptanceUnknownError) Unwrap() []error {
	return []error{ErrAcceptanceUnknown, e.cause}
}

// IsCorruption reports whether err proves a durable queue integrity violation.
func IsCorruption(err error) bool {
	return errors.Is(err, ErrCorrupt)
}

// IsAcceptanceUnknown reports an indeterminate Add acceptance outcome.
func IsAcceptanceUnknown(err error) bool {
	return errors.Is(err, ErrAcceptanceUnknown)
}

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

func acceptanceUnknown(cause error) error {
	return &acceptanceUnknownError{cause: cause}
}

func definiteAcceptanceCause(err error) error {
	var unknown *acceptanceUnknownError

	if errors.As(err, &unknown) {
		return unknown.cause
	}

	return err
}

func corruptionf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}
