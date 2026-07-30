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
//     is rejected after a reclaim sweep when nothing is reclaimable.
//
// Complexity:
//
//   - Existing identity reserve: expected O(1). Periodic expiry may run a full sweep
//     only when pruneInterval has elapsed.
//   - New identity below capacity: expected O(1).
//   - New identity at capacity: may perform one full expiry/capacity sweep. After a
//     sweep finds nothing reclaimable at this logical time, further new-identity
//     rejections at the same time are O(1) without rescanning.
//
// Terminal ops:
//
//	reserve   — budget check on IP and identity; atomically create needed entries
//	            and increment in-flight on both.
//	failed    — convert one matching reservation into one failure on both.
//	canceled  — release one matching in-flight on both; drop emptied identity/IP.
//	succeeded — release one in-flight on both; clear exact-identity failures and
//	            subtract only that contribution from the IP aggregate; drop empties.
type authLimiter struct {
	mu     sync.Mutex
	byIP   map[string]*attemptState
	byKey  map[string]*attemptState
	pruned time.Time
	clock  func() time.Time

	maxIP      int
	maxKey     int
	expiry     time.Duration
	pruneEvery time.Duration

	// atCapSweepAt is the last logical time a capacity sweep found nothing reclaimable.
	// Repeated new identities at the same logical time skip further full sweeps.
	atCapSweepAt time.Time

	// fullSweeps counts complete map sweeps (tests only).
	fullSweeps int
}

func newAuthLimiter() *authLimiter {
	return newAuthLimiterSized(maxAuthIPEntries, maxAuthKeyEntries, entryExpiry, entryExpiry)
}

func newAuthLimiterSized(maxIP, maxKey int, expiry, pruneEvery time.Duration) *authLimiter {
	if maxIP <= 0 {
		maxIP = maxAuthIPEntries
	}
	if maxKey <= 0 {
		maxKey = maxAuthKeyEntries
	}
	if expiry <= 0 {
		expiry = entryExpiry
	}
	if pruneEvery <= 0 {
		pruneEvery = entryExpiry
	}
	now := time.Now()
	return &authLimiter{
		byIP:       make(map[string]*attemptState),
		byKey:      make(map[string]*attemptState),
		pruned:     now,
		clock:      time.Now,
		maxIP:      maxIP,
		maxKey:     maxKey,
		expiry:     expiry,
		pruneEvery: pruneEvery,
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
func (l *authLimiter) safeToPrune(st *attemptState, now time.Time) bool {
	if st == nil {
		return true
	}
	if st.inFlight > 0 || now.Before(st.until) {
		return false
	}
	if emptyState(st, now) {
		return true
	}
	return now.Sub(st.seen) > l.expiry
}

// reserve attempts to reserve an authentication slot for the given IP and username.
func (l *authLimiter) reserve(ip, username string) bool {
	now := l.nowTime()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.maybePeriodicPrune(now)

	ipKey, key := canonicalLimiterKey(ip, username)
	ipState := l.byIP[ipKey]
	keyState := l.byKey[key]

	needNewIP := ipState == nil
	needNewKey := keyState == nil

	if needNewIP || needNewKey {
		if (needNewIP && len(l.byIP) >= l.maxIP) || (needNewKey && len(l.byKey) >= l.maxKey) {
			// Capacity may reclaim expired entries once per logical time after a dry sweep.
			if !l.atCapSweepAt.Equal(now) {
				reclaimed := l.forcePrune(now)
				if !reclaimed {
					l.atCapSweepAt = now
				}
				ipState = l.byIP[ipKey]
				keyState = l.byKey[key]
				needNewIP = ipState == nil
				needNewKey = keyState == nil
			}
			if needNewIP && len(l.byIP) >= l.maxIP {
				return false
			}
			if needNewKey && len(l.byKey) >= l.maxKey {
				return false
			}
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
	l.dropEmpty(key, ipKey, now)
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
	if emptyState(keyState, now) {
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

func (l *authLimiter) dropEmpty(key, ipKey string, now time.Time) {
	if st := l.byKey[key]; emptyState(st, now) {
		delete(l.byKey, key)
	}
	if st := l.byIP[ipKey]; emptyState(st, now) {
		delete(l.byIP, ipKey)
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

func (l *authLimiter) maybePeriodicPrune(now time.Time) {
	if now.Sub(l.pruned) < l.pruneEvery {
		return
	}
	l.forcePrune(now)
}

// forcePrune performs a full expiry sweep. Returns true if any entry was removed.
func (l *authLimiter) forcePrune(now time.Time) bool {
	l.pruned = now
	l.fullSweeps++
	reclaimed := false

	// Prune identities first so IP aggregates can be adjusted consistently.
	for k, st := range l.byKey {
		if !l.safeToPrune(st, now) {
			continue
		}
		l.dropIdentityLocked(k, st, now)
		reclaimed = true
	}
	for k, st := range l.byIP {
		if l.safeToPrune(st, now) {
			delete(l.byIP, k)
			reclaimed = true
		}
	}
	return reclaimed
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
	if len(l.byIP) > l.maxIP {
		return fmt.Errorf("byIP over capacity: %d > %d", len(l.byIP), l.maxIP)
	}
	if len(l.byKey) > l.maxKey {
		return fmt.Errorf("byKey over capacity: %d > %d", len(l.byKey), l.maxKey)
	}
	return nil
}
