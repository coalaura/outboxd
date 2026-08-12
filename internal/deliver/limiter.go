package deliver

import (
	"sync"
)

type slot struct {
	holders int
}

type domainLimiter struct {
	limit int

	mu    sync.Mutex
	slots map[string]*slot
}

// tryAcquire reserves domain capacity without creating a waiter.
func (l *domainLimiter) tryAcquire(domain string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if domain == "" {
		return true
	}

	entry := l.slots[domain]
	if entry != nil && entry.holders >= l.limit {
		return false
	}

	if entry == nil {
		entry = &slot{}

		l.slots[domain] = entry
	}

	entry.holders++

	return true
}

func (l *domainLimiter) release(domain string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.slots[domain]
	if !ok {
		return
	}

	entry.holders--
	if entry.holders <= 0 {
		delete(l.slots, domain)
	}
}

func newDomainLimiter(limit int) *domainLimiter {
	if limit < 1 {
		limit = 1
	}

	return &domainLimiter{
		limit: limit,
		slots: make(map[string]*slot),
	}
}
