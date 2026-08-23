package queue

import (
	"math"
	"time"
)

const (
	StatusPending Status = "pending"
	StatusSent    Status = "sent"
	StatusFailed  Status = "failed"
)

const (
	maxEnvelopeMetadata    = 4 << 20
	maxEnvelopeRecipients  = 1000
	maxEnvelopeStringBytes = 4096
	maxEnvelopeDetailBytes = 64 << 10
	maxEnvelopeAttempts    = 1 << 20
	maxEnvelopeRevision    = math.MaxUint64 - 1
	bodyDigestPrefix       = "sha256:"
)

// Status is the delivery state of a single recipient.
type Status string

// Body identifies one immutable message variant within the stored body file.
type Body struct {
	Offset   int64  `json:"offset"`
	Size     int64  `json:"size"`
	Digest   string `json:"digest"`
	EightBit bool   `json:"eight_bit,omitempty"`
}

// Recipient is one envelope recipient and its delivery outcome.
type Recipient struct {
	Address      string `json:"address"`
	Domain       string `json:"domain"`
	Body         int    `json:"body,omitempty"`
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
	Bodies      []Body      `json:"bodies,omitempty"`
	Size        int64       `json:"size"`
	Created     time.Time   `json:"created"`
	Attempts    int         `json:"attempts"`
	NextAttempt time.Time   `json:"next_attempt"`
	LastError   string      `json:"last_error,omitempty"`
	SMTPUTF8    bool        `json:"smtp_utf8,omitempty"`
	EightBit    bool        `json:"eight_bit,omitempty"`
	BodyDigest  string      `json:"body_digest"`

	// DSNID links a source to the exact DSN durably created for this generation.
	DSNID string `json:"dsn_id,omitempty"`

	// DSNSourceID is set on generated DSNs, preventing recursive notifications
	// and allowing recovery to verify the reciprocal source identity.
	DSNSourceID          string `json:"dsn_source_id,omitempty"`
	DSNSourceIncarnation string `json:"dsn_source_incarnation,omitempty"`
	DSNSourceRevision    uint64 `json:"dsn_source_revision,omitempty"`
	DSNGeneration        uint64 `json:"dsn_generation,omitempty"`

	// EnqueuedAt is used by quota accounting for in-progress adds.
	EnqueuedAt time.Time `json:"-"`

	// PreferredDomain is transient scheduler state for resuming a multi-domain
	// envelope after capacity becomes available.
	PreferredDomain string `json:"-"`

	index int
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

// MessageSize reports the immutable body size selected for one recipient.
func (e *Envelope) MessageSize(recipient int) int64 {
	if len(e.Bodies) == 0 {
		return e.Size
	}

	return e.Bodies[e.Recipients[recipient].Body].Size
}

// MessageEightBit reports whether one recipient's body requires 8BITMIME.
func (e *Envelope) MessageEightBit(recipient int) bool {
	if len(e.Bodies) == 0 {
		return e.EightBit
	}

	return e.Bodies[e.Recipients[recipient].Body].EightBit
}

// NewBody describes data at offset in a concatenated immutable body file.
func NewBody(offset int64, data []byte, eightBit bool) Body {
	return Body{
		Offset:   offset,
		Size:     int64(len(data)),
		Digest:   bodyDigest(data),
		EightBit: eightBit,
	}
}

func cloneEnvelope(envelope *Envelope) *Envelope {
	clone := *envelope

	clone.Recipients = append([]Recipient(nil), envelope.Recipients...)
	clone.Bodies = append([]Body(nil), envelope.Bodies...)
	clone.index = -1

	return &clone
}
