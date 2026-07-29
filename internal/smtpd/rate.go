package smtpd

import (
	"sync"
	"time"
)

type submissionAllowance struct {
	messages   float64
	recipients float64
	updated    time.Time
}

type submissionLimiter struct {
	maxMessages   int
	maxRecipients int

	mu      sync.Mutex
	entries map[string]*submissionAllowance
}

func newSubmissionLimiter(maxMessages, maxRecipients int) *submissionLimiter {
	return &submissionLimiter{
		maxMessages:   maxMessages,
		maxRecipients: maxRecipients,
		entries:       make(map[string]*submissionAllowance),
	}
}

func (l *submissionLimiter) take(username string, recipients int) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	allowance, ok := l.entries[username]
	if !ok {
		allowance = &submissionAllowance{
			messages:   float64(l.maxMessages),
			recipients: float64(l.maxRecipients),
			updated:    now,
		}

		l.entries[username] = allowance
	}

	l.refill(allowance, now)

	if allowance.messages < 1 || allowance.recipients < float64(recipients) {
		return false
	}

	allowance.messages--
	allowance.recipients -= float64(recipients)

	return true
}

func (l *submissionLimiter) refund(username string, recipients int) {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	allowance, ok := l.entries[username]
	if !ok {
		return
	}

	l.refill(allowance, now)

	allowance.messages = min(allowance.messages+1, float64(l.maxMessages))
	allowance.recipients = min(allowance.recipients+float64(recipients), float64(l.maxRecipients))
}

func (l *submissionLimiter) refill(allowance *submissionAllowance, now time.Time) {
	elapsed := now.Sub(allowance.updated)

	allowance.updated = now

	if elapsed <= 0 {
		return
	}

	hours := elapsed.Hours()

	allowance.messages = min(
		allowance.messages+hours*float64(l.maxMessages),
		float64(l.maxMessages),
	)

	allowance.recipients = min(
		allowance.recipients+hours*float64(l.maxRecipients),
		float64(l.maxRecipients),
	)
}
