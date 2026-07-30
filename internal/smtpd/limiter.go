package smtpd

import (
	"strings"
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
	// inFlight counts reserved authentication attempts currently in progress.
	inFlight int
}

// authLimiter tracks per-IP and per-IP+canonicalUsername authentication attempts.
//
// State machine (under mu):
//
//	reserve  — if not locked and failures+inFlight < freeAttempts (or post-lockout
//	           single-flight), increment inFlight on IP and IP+user budgets.
//	failed   — decrement inFlight, increment failures; when failures >= freeAttempts
//	           set exponential lockout until.
//	canceled — decrement inFlight only (no failure, no success reset).
//	succeeded — decrement inFlight; clear failures for the exact IP+user identity only
//	            (IP-level failures from other usernames are preserved).
type authLimiter struct {
	mu     sync.Mutex
	byIP   map[string]*attemptState
	byKey  map[string]*attemptState
	pruned time.Time
	clock  func() time.Time
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{
		byIP:   make(map[string]*attemptState),
		byKey:  make(map[string]*attemptState),
		pruned: time.Now(),
		clock:  time.Now,
	}
}

func (l *authLimiter) nowTime() time.Time {
	if l.clock != nil {
		return l.clock()
	}
	return time.Now()
}

func canonicalLimiterKey(ip, username string) (string, string) {
	canonUser := strings.ToLower(strings.TrimSpace(username))
	return ip, ip + "\x00" + canonUser
}

// canReserve reports whether st permits another reservation at now.
// Outstanding reservations count toward the free-attempt threshold.
func canReserve(st *attemptState, now time.Time) bool {
	if st == nil {
		return true
	}
	if now.Before(st.until) {
		return false
	}
	if st.failures < freeAttempts {
		// Free phase: at most freeAttempts failed-or-reserved total.
		return st.failures+st.inFlight < freeAttempts
	}
	// Past freeAttempts: lockout must have expired (checked above); allow one in-flight try.
	return st.inFlight == 0
}

// reserve attempts to reserve an authentication slot for the given IP and username.
func (l *authLimiter) reserve(ip, username string) bool {
	now := l.nowTime()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.prune(now)
	ipKey, key := canonicalLimiterKey(ip, username)

	if len(l.byIP)+len(l.byKey) > maxAuthEntries {
		l.forcePrune(now)
		if len(l.byIP)+len(l.byKey) > maxAuthEntries {
			return false
		}
	}

	ipState := l.byIP[ipKey]
	keyState := l.byKey[key]
	if !canReserve(ipState, now) || !canReserve(keyState, now) {
		return false
	}

	if ipState == nil {
		ipState = new(attemptState)
		l.byIP[ipKey] = ipState
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

// failed records a failed authentication attempt.
func (l *authLimiter) failed(ip, username string) {
	now := l.nowTime()
	l.mu.Lock()
	defer l.mu.Unlock()

	ipKey, key := canonicalLimiterKey(ip, username)
	l.recordFail(l.byIP, ipKey, now)
	l.recordFail(l.byKey, key, now)
}

// canceled releases an in-flight reservation without recording a failure or resetting failures.
func (l *authLimiter) canceled(ip, username string) {
	now := l.nowTime()
	l.mu.Lock()
	defer l.mu.Unlock()

	ipKey, key := canonicalLimiterKey(ip, username)
	l.releaseInFlight(l.byIP, ipKey, now)
	l.releaseInFlight(l.byKey, key, now)
}

// succeeded clears failures for the exact IP+username identity, preserving unrelated IP failures.
func (l *authLimiter) succeeded(ip, username string) {
	now := l.nowTime()
	l.mu.Lock()
	defer l.mu.Unlock()

	ipKey, key := canonicalLimiterKey(ip, username)

	if st := l.byIP[ipKey]; st != nil {
		if st.inFlight > 0 {
			st.inFlight--
		}
		st.seen = now
	}

	if st := l.byKey[key]; st != nil {
		if st.inFlight > 0 {
			st.inFlight--
		}
		st.failures = 0
		st.until = time.Time{}
		st.seen = now
		if st.inFlight == 0 {
			delete(l.byKey, key)
		}
	}
}

func (l *authLimiter) releaseInFlight(m map[string]*attemptState, key string, now time.Time) {
	st := m[key]
	if st == nil {
		return
	}
	if st.inFlight > 0 {
		st.inFlight--
	}
	st.seen = now
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

	if st.failures < freeAttempts {
		return
	}
	// Lockout policy applies once freeAttempts is reached.
	shift := st.failures - freeAttempts
	if shift > 10 {
		shift = 10
	}
	lockout := lockoutBase << shift
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
		// Never prune entries with active reservations.
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
