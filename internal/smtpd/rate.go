package smtpd

import (
	"sync"
	"time"
)

type submissionAllowance struct {
	messages   float64
	recipients float64
	updated    time.Time
	seen       time.Time
}

type submissionLimiter struct {
	maxMessages   float64
	maxRecipients float64
	msgBurst      float64
	rcptBurst     float64

	mu      sync.Mutex
	entries map[string]*submissionAllowance
	pruned  time.Time
}

const maxRateEntries = 10000

func newSubmissionLimiter(maxMessages, maxRecipients, msgBurst, rcptBurst int) *submissionLimiter {
	if msgBurst <= 0 {
		msgBurst = 1
	}

	if rcptBurst <= 0 {
		rcptBurst = 1
	}

	if msgBurst > maxMessages && maxMessages > 0 {
		msgBurst = maxMessages
	}

	if rcptBurst > maxRecipients && maxRecipients > 0 {
		rcptBurst = maxRecipients
	}

	return &submissionLimiter{
		maxMessages:   float64(maxMessages),
		maxRecipients: float64(maxRecipients),
		msgBurst:      float64(msgBurst),
		rcptBurst:     float64(rcptBurst),
		entries:       make(map[string]*submissionAllowance),
		pruned:        time.Now(),
	}
}

func (l *submissionLimiter) take(username string, recipients int) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.prune(now)

	allowance, ok := l.entries[username]
	if !ok {
		// Start with burst only, not a full hourly allowance.
		allowance = &submissionAllowance{
			messages:   l.msgBurst,
			recipients: l.rcptBurst,
			updated:    now,
			seen:       now,
		}

		if len(l.entries) >= maxRateEntries {
			l.forcePrune(now)

			if len(l.entries) >= maxRateEntries {
				return false
			}
		}

		l.entries[username] = allowance
	}

	l.refill(allowance, now)

	allowance.seen = now

	if allowance.messages < 1 || allowance.recipients < float64(recipients) {
		return false
	}

	allowance.messages--
	allowance.recipients -= float64(recipients)

	return true
}

func (l *submissionLimiter) refill(a *submissionAllowance, now time.Time) {
	elapsed := now.Sub(a.updated)

	a.updated = now
	if elapsed <= 0 {
		return
	}

	hours := elapsed.Hours()

	// Cap accumulated tokens at the burst size, not the full hourly rate.
	a.messages = min(a.messages+hours*l.maxMessages, l.msgBurst)
	a.recipients = min(a.recipients+hours*l.maxRecipients, l.rcptBurst)
}

func (l *submissionLimiter) prune(now time.Time) {
	if now.Sub(l.pruned) < entryExpiry {
		return
	}

	l.forcePrune(now)
}

func (l *submissionLimiter) forcePrune(now time.Time) {
	l.pruned = now

	for k, a := range l.entries {
		if now.Sub(a.seen) > entryExpiry {
			delete(l.entries, k)
		}
	}
}
