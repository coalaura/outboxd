package smtpd

import (
	"sync"
	"time"
)

const (
	freeAttempts   = 5
	lockoutBase    = 2 * time.Second
	lockoutMax     = 5 * time.Minute
	entryExpiry    = 30 * time.Minute
	maxAuthEntries = 10000
)

type attemptState struct {
	failures int
	until    time.Time
	seen     time.Time
	// inFlight is incremented atomically under the lock while an attempt is
	// reserved so concurrent authentications cannot all pass the same allow.
	inFlight int
}

// authLimiter tracks per-IP and per-IP+username authentication attempts.
type authLimiter struct {
	mu     sync.Mutex
	byIP   map[string]*attemptState
	byKey  map[string]*attemptState
	pruned time.Time
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{
		byIP:   make(map[string]*attemptState),
		byKey:  make(map[string]*attemptState),
		pruned: time.Now(),
	}
}

// reserve returns false if the IP or IP+user is currently locked out.
// On true, a concurrent slot is held until success or fail is recorded.
func (l *authLimiter) reserve(ip, username string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.prune(now)
	if len(l.byIP)+len(l.byKey) > maxAuthEntries {
		// Drop oldest-looking entries by full prune rehash under pressure.
		l.forcePrune(now)
		if len(l.byIP)+len(l.byKey) > maxAuthEntries {
			return false
		}
	}

	ipState := l.byIP[ip]
	if ipState != nil {
		ipState.seen = now
		if !now.After(ipState.until) {
			return false
		}
	}

	key := ip + "\x00" + username
	keyState := l.byKey[key]
	if keyState != nil {
		keyState.seen = now
		if !now.After(keyState.until) {
			return false
		}
	}

	if ipState == nil {
		ipState = new(attemptState)
		l.byIP[ip] = ipState
	}
	if keyState == nil {
		keyState = new(attemptState)
		l.byKey[key] = keyState
	}
	ipState.inFlight++
	keyState.inFlight++
	ipState.seen = now
	keyState.seen = now
	return true
}

func (l *authLimiter) failed(ip, username string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.recordFail(l.byIP, ip, now)
	l.recordFail(l.byKey, ip+"\x00"+username, now)
}

func (l *authLimiter) succeeded(ip, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if st := l.byIP[ip]; st != nil {
		st.inFlight--
		if st.inFlight < 0 {
			st.inFlight = 0
		}
		if st.inFlight == 0 && st.failures == 0 {
			delete(l.byIP, ip)
		} else {
			st.failures = 0
			st.until = time.Time{}
		}
	}
	key := ip + "\x00" + username
	if st := l.byKey[key]; st != nil {
		st.inFlight--
		if st.inFlight <= 0 {
			delete(l.byKey, key)
		}
	}
}

func (l *authLimiter) recordFail(m map[string]*attemptState, key string, now time.Time) {
	st := m[key]
	if st == nil {
		st = new(attemptState)
		m[key] = st
	}
	if st.inFlight > 0 {
		st.inFlight--
	}
	st.failures++
	st.seen = now
	if st.failures <= freeAttempts {
		return
	}
	lockout := lockoutBase << min(st.failures-freeAttempts-1, 10)
	st.until = now.Add(min(lockout, lockoutMax))
}

func (l *authLimiter) prune(now time.Time) {
	if now.Sub(l.pruned) < entryExpiry {
		return
	}
	l.forcePrune(now)
}

func (l *authLimiter) forcePrune(now time.Time) {
	l.pruned = now
	for k, st := range l.byIP {
		if st.inFlight == 0 && now.Sub(st.seen) > entryExpiry {
			delete(l.byIP, k)
		}
	}
	for k, st := range l.byKey {
		if st.inFlight == 0 && now.Sub(st.seen) > entryExpiry {
			delete(l.byKey, k)
		}
	}
}
