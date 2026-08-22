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

func cloneEnvelope(envelope *Envelope) *Envelope {
	clone := *envelope

	clone.Recipients = append([]Recipient(nil), envelope.Recipients...)
	clone.index = -1

	return &clone
}
