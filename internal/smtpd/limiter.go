package smtpd

import (
	"sync"
	"time"
)

const (
	freeAttempts = 5
	lockoutBase  = 2 * time.Second
	lockoutMax   = 5 * time.Minute
	entryExpiry  = 30 * time.Minute
)

type attempts struct {
	failures int
	until    time.Time
	seen     time.Time
}

type limiter struct {
	mu      sync.Mutex
	entries map[string]*attempts
	pruned  time.Time
}

func newLimiter() *limiter {
	return &limiter{
		entries: make(map[string]*attempts),
		pruned:  time.Now(),
	}
}

func (l *limiter) allow(ip string) bool {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.prune(now)

	entry, ok := l.entries[ip]
	if !ok {
		return true
	}

	entry.seen = now

	return now.After(entry.until)
}

func (l *limiter) failed(ip string) {
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[ip]
	if !ok {
		entry = new(attempts)
		l.entries[ip] = entry
	}

	entry.failures++
	entry.seen = now

	if entry.failures <= freeAttempts {
		return
	}

	lockout := lockoutBase << min(entry.failures-freeAttempts-1, 10)
	entry.until = now.Add(min(lockout, lockoutMax))
}

func (l *limiter) succeeded(ip string) {
	l.mu.Lock()
	delete(l.entries, ip)
	l.mu.Unlock()
}

func (l *limiter) prune(now time.Time) {
	if now.Sub(l.pruned) < entryExpiry {
		return
	}

	l.pruned = now

	for ip, entry := range l.entries {
		if now.Sub(entry.seen) > entryExpiry {
			delete(l.entries, ip)
		}
	}
}
