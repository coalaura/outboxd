package deliver

import (
	"context"
	"sync"
)

type slot struct {
	tokens  chan struct{}
	holders int
}

type domainLimiter struct {
	limit int

	mu    sync.Mutex
	slots map[string]*slot
}

func newDomainLimiter(limit int) *domainLimiter {
	return &domainLimiter{
		limit: limit,
		slots: make(map[string]*slot),
	}
}

func (l *domainLimiter) acquire(ctx context.Context, domain string) error {
	l.mu.Lock()

	entry, ok := l.slots[domain]
	if !ok {
		entry = &slot{tokens: make(chan struct{}, l.limit)}

		l.slots[domain] = entry
	}

	entry.holders++
	l.mu.Unlock()

	select {
	case entry.tokens <- struct{}{}:
		return nil
	case <-ctx.Done():
		l.drop(domain)

		return ctx.Err()
	}
}

func (l *domainLimiter) release(domain string) {
	l.mu.Lock()
	entry, ok := l.slots[domain]
	l.mu.Unlock()

	if !ok {
		return
	}

	<-entry.tokens

	l.drop(domain)
}

func (l *domainLimiter) drop(domain string) {
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
