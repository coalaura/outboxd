package smtpd

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	freeAttempts = 5
	lockoutBase  = 2 * time.Second
	lockoutMax   = 5 * time.Minute
	entryExpiry  = 30 * time.Minute

	// Separate caps so filling one map cannot masquerade as capacity for the other.
	maxAuthIPEntries  = 10000
	maxAuthKeyEntries = 10000
)

// attemptState tracks failures and in-flight reservations for one identity key
// (source IP aggregate or IP+canonical-username).
type attemptState struct {
	failures int
	until    time.Time
	seen     time.Time
	// inFlight counts reserved authentication attempts currently in progress.
	inFlight int
}

// authLimiter tracks per-IP and per-IP+canonicalUsername authentication attempts.
//
// State model (under mu):
//
//   - byKey holds exact IP+username identities. Each completed failure contributes
//     exactly once to the identity and once to the source-IP aggregate.
//   - byIP holds the source-IP aggregate. IP failure and in-flight totals must always
//     equal the sum of retained identity contributions for that IP.
//   - Capacity is enforced separately on byIP and byKey. Existing identities may
//     still reserve when maps are at capacity; only creation of a new key/IP entry
//     is rejected after prune.
//
// Terminal ops:
//
//	reserve   — budget check on IP and identity; atomically create needed entries
//	            and increment in-flight on both.
//	failed    — convert one matching reservation into one failure on both.
//	canceled  — release one matching in-flight on both (no failure change).
//	succeeded — release one in-flight on both; clear exact-identity failures and
//	            subtract only that contribution from the IP aggregate.
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

func ipFromKey(key string) string {
	ip, _, _ := strings.Cut(key, "\x00")
	return ip
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
		return st.failures+st.inFlight < freeAttempts
	}
	// Past freeAttempts: lockout must have expired (checked above); one in-flight try.
	return st.inFlight == 0
}

// emptyState is safe to remove eagerly: no failures, no reservations, no lockout.
func emptyState(st *attemptState, now time.Time) bool {
	return st != nil && st.failures == 0 && st.inFlight == 0 && !now.Before(st.until)
}

// safeToPrune: expired idle, or empty. Never prune active reservations or lockouts.
func safeToPrune(st *attemptState, now time.Time) bool {
	if st == nil {
		return true
	}
	if st.inFlight > 0 || now.Before(st.until) {
		return false
	}
	if emptyState(st, now) {
		return true
	}
	return now.Sub(st.seen) > entryExpiry
}

// reserve attempts to reserve an authentication slot for the given IP and username.
func (l *authLimiter) reserve(ip, username string) bool {
	now := l.nowTime()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.prune(now)
	l.removeEmpty(now)

	ipKey, key := canonicalLimiterKey(ip, username)
	ipState := l.byIP[ipKey]
	keyState := l.byKey[key]

	needNewIP := ipState == nil
	needNewKey := keyState == nil

	if needNewIP || needNewKey {
		// Prune expired entries again before rejecting new identities.
		l.forcePrune(now)
		l.removeEmpty(now)
		ipState = l.byIP[ipKey]
		keyState = l.byKey[key]
		needNewIP = ipState == nil
		needNewKey = keyState == nil

		if needNewIP && len(l.byIP) >= maxAuthIPEntries {
			return false
		}
		if needNewKey && len(l.byKey) >= maxAuthKeyEntries {
			return false
		}
	}

	if !canReserve(ipState, now) || !canReserve(keyState, now) {
		return false
	}

	// Atomic multi-entry create: allocate both before publishing either when both are new.
	if needNewIP {
		ipState = new(attemptState)
	}
	if needNewKey {
		keyState = new(attemptState)
	}
	if needNewIP {
		l.byIP[ipKey] = ipState
	}
	if needNewKey {
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
	// Require a matching identity reservation so mismatched terminals cannot
	// corrupt IP aggregates or create half-entries.
	st := l.byKey[key]
	if st == nil || st.inFlight == 0 {
		return
	}
	l.convertFail(l.byKey, key, now)
	l.convertFail(l.byIP, ipKey, now)
}

// canceled releases an in-flight reservation without recording a failure or resetting failures.
func (l *authLimiter) canceled(ip, username string) {
	now := l.nowTime()
	l.mu.Lock()
	defer l.mu.Unlock()

	ipKey, key := canonicalLimiterKey(ip, username)
	st := l.byKey[key]
	if st == nil || st.inFlight == 0 {
		return
	}
	l.releaseInFlight(l.byKey, key, now)
	l.releaseInFlight(l.byIP, ipKey, now)
	l.removeEmpty(now)
}

// succeeded clears failures for the exact IP+username identity, subtracting only
// that identity's prior failure contribution from the IP aggregate.
func (l *authLimiter) succeeded(ip, username string) {
	now := l.nowTime()
	l.mu.Lock()
	defer l.mu.Unlock()

	ipKey, key := canonicalLimiterKey(ip, username)

	keyState := l.byKey[key]
	if keyState == nil || keyState.inFlight == 0 {
		return
	}

	// Exact identity contribution before clearing.
	cleared := 0
	if keyState.inFlight > 0 {
		keyState.inFlight--
	}
	cleared = keyState.failures
	keyState.failures = 0
	keyState.until = time.Time{}
	keyState.seen = now
	if keyState.inFlight == 0 && keyState.failures == 0 {
		delete(l.byKey, key)
	}

	if ipState := l.byIP[ipKey]; ipState != nil {
		if ipState.inFlight > 0 {
			ipState.inFlight--
		}
		if cleared > 0 {
			if ipState.failures >= cleared {
				ipState.failures -= cleared
			} else {
				ipState.failures = 0
			}
		}
		if ipState.failures < freeAttempts {
			ipState.until = time.Time{}
		}
		ipState.seen = now
		if emptyState(ipState, now) {
			delete(l.byIP, ipKey)
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

func (l *authLimiter) convertFail(m map[string]*attemptState, key string, now time.Time) {
	st := m[key]
	if st == nil {
		// Mismatched terminal without a prior reservation: do not create ghost state.
		return
	}
	if st.inFlight > 0 {
		st.inFlight--
	}
	st.failures++
	st.seen = now

	if st.failures < freeAttempts {
		return
	}
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

	// Prune identities first so IP aggregates can be adjusted consistently.
	for k, st := range l.byKey {
		if !safeToPrune(st, now) {
			continue
		}
		l.dropIdentityLocked(k, st, now)
	}
	for k, st := range l.byIP {
		if safeToPrune(st, now) {
			delete(l.byIP, k)
		}
	}
}

// dropIdentityLocked removes an identity and subtracts its contributions from the IP aggregate.
func (l *authLimiter) dropIdentityLocked(key string, st *attemptState, now time.Time) {
	ip := ipFromKey(key)
	if ipState := l.byIP[ip]; ipState != nil {
		if st.failures > 0 {
			if ipState.failures >= st.failures {
				ipState.failures -= st.failures
			} else {
				ipState.failures = 0
			}
		}
		if st.inFlight > 0 {
			if ipState.inFlight >= st.inFlight {
				ipState.inFlight -= st.inFlight
			} else {
				ipState.inFlight = 0
			}
		}
		if ipState.failures < freeAttempts {
			ipState.until = time.Time{}
		}
		ipState.seen = now
		if emptyState(ipState, now) {
			delete(l.byIP, ip)
		}
	}
	delete(l.byKey, key)
}

func (l *authLimiter) removeEmpty(now time.Time) {
	for k, st := range l.byKey {
		if emptyState(st, now) {
			delete(l.byKey, k)
		}
	}
	for k, st := range l.byIP {
		if emptyState(st, now) {
			delete(l.byIP, k)
		}
	}
}

// assertAggregatesLocked verifies IP totals equal the sum of identity contributions.
// Used only by tests; panics on violation so race tests surface corruption quickly.
func (l *authLimiter) assertAggregatesLocked() error {
	type sum struct {
		fail, inflight int
	}
	want := make(map[string]sum)
	for k, st := range l.byKey {
		ip := ipFromKey(k)
		s := want[ip]
		s.fail += st.failures
		s.inflight += st.inFlight
		want[ip] = s
		if st.failures < 0 || st.inFlight < 0 {
			return fmt.Errorf("negative identity state key=%q failures=%d inFlight=%d", k, st.failures, st.inFlight)
		}
	}
	for ip, st := range l.byIP {
		if st.failures < 0 || st.inFlight < 0 {
			return fmt.Errorf("negative IP state ip=%q failures=%d inFlight=%d", ip, st.failures, st.inFlight)
		}
		s := want[ip]
		if st.failures != s.fail || st.inFlight != s.inflight {
			return fmt.Errorf("aggregate mismatch ip=%q got fail=%d inFlight=%d want fail=%d inFlight=%d",
				ip, st.failures, st.inFlight, s.fail, s.inflight)
		}
		delete(want, ip)
	}
	for ip, s := range want {
		if s.fail != 0 || s.inflight != 0 {
			return fmt.Errorf("missing IP aggregate ip=%q fail=%d inFlight=%d", ip, s.fail, s.inflight)
		}
	}
	if len(l.byIP) > maxAuthIPEntries {
		return fmt.Errorf("byIP over capacity: %d > %d", len(l.byIP), maxAuthIPEntries)
	}
	if len(l.byKey) > maxAuthKeyEntries {
		return fmt.Errorf("byKey over capacity: %d > %d", len(l.byKey), maxAuthKeyEntries)
	}
	return nil
}
