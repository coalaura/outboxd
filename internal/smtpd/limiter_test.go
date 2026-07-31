package smtpd

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func checkAgg(t *testing.T, l *authLimiter) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.assertAggregatesLocked(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthLimiterConcurrentReserveBudget(t *testing.T) {
	l := newAuthLimiter()
	const n = 50
	start := make(chan struct{})
	var wg sync.WaitGroup
	var okCount atomic.Int32

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if l.reserve("10.0.0.1", "alice") {
				okCount.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := okCount.Load(); got != int32(freeAttempts) {
		t.Fatalf("accepted=%d want %d (freeAttempts)", got, freeAttempts)
	}
	checkAgg(t, l)
}

func TestAuthLimiterConcurrentFailuresLockout(t *testing.T) {
	l := newAuthLimiter()
	var wg sync.WaitGroup
	start := make(chan struct{})
	const n = 20
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if l.reserve("10.0.0.2", "bob") {
				l.failed("10.0.0.2", "bob")
			}
		}()
	}
	close(start)
	wg.Wait()

	if l.reserve("10.0.0.2", "bob") {
		t.Fatal("should be locked out after concurrent failures")
	}
	checkAgg(t, l)
}

func TestAuthLimiterCanceledReleasesWithoutReset(t *testing.T) {
	l := newAuthLimiter()
	for i := 0; i < freeAttempts-1; i++ {
		if !l.reserve("1.2.3.4", "u") {
			t.Fatal("reserve")
		}
		l.failed("1.2.3.4", "u")
	}
	if !l.reserve("1.2.3.4", "u") {
		t.Fatal("reserve before cancel")
	}
	l.canceled("1.2.3.4", "u")

	if !l.reserve("1.2.3.4", "u") {
		t.Fatal("expected reserve after cancel")
	}
	l.failed("1.2.3.4", "u")
	if l.reserve("1.2.3.4", "u") {
		t.Fatal("expected lockout")
	}
	checkAgg(t, l)
}

func TestAuthLimiterSuccessClearsOnlyIdentityContribution(t *testing.T) {
	l := newAuthLimiter()
	// Alice and Bob share an IP (stay under freeAttempts aggregate so success can reserve).
	for i := 0; i < 2; i++ {
		if !l.reserve("9.9.9.9", "alice") {
			t.Fatal("reserve alice")
		}
		l.failed("9.9.9.9", "alice")
	}
	for i := 0; i < 2; i++ {
		if !l.reserve("9.9.9.9", "bob") {
			t.Fatal("reserve bob")
		}
		l.failed("9.9.9.9", "bob")
	}
	checkAgg(t, l)

	if !l.reserve("9.9.9.9", "alice") {
		t.Fatal("reserve alice success")
	}
	l.succeeded("9.9.9.9", "alice")
	checkAgg(t, l)

	l.mu.Lock()
	ipFail := 0
	if st := l.byIP["9.9.9.9"]; st != nil {
		ipFail = st.failures
	}
	_, aliceKey := l.byKey["9.9.9.9\x00alice"]
	bobFail := 0
	if st := l.byKey["9.9.9.9\x00bob"]; st != nil {
		bobFail = st.failures
	}
	l.mu.Unlock()

	if aliceKey {
		t.Fatal("alice key should be removed after success with no in-flight")
	}
	if bobFail != 2 {
		t.Fatalf("bob identity failures=%d want 2", bobFail)
	}
	if ipFail != 2 {
		t.Fatalf("IP failures=%d want 2 (bob only)", ipFail)
	}

	// Later Alice failure is counted normally.
	if !l.reserve("9.9.9.9", "alice") {
		t.Fatal("alice after clear")
	}
	l.failed("9.9.9.9", "alice")
	checkAgg(t, l)
	l.mu.Lock()
	ipFail = l.byIP["9.9.9.9"].failures
	aliceFail := l.byKey["9.9.9.9\x00alice"].failures
	l.mu.Unlock()
	if aliceFail != 1 || ipFail != 3 {
		t.Fatalf("after alice fail: alice=%d ip=%d", aliceFail, ipFail)
	}
}

func TestAuthLimiterSuccessClearsIdentityFailuresFromIP(t *testing.T) {
	l := newAuthLimiter()
	for i := 0; i < 2; i++ {
		if !l.reserve("8.8.8.8", "bob") {
			t.Fatal("reserve")
		}
		l.failed("8.8.8.8", "bob")
	}
	if !l.reserve("8.8.8.8", "bob") {
		t.Fatal("reserve before success")
	}
	l.succeeded("8.8.8.8", "bob")
	checkAgg(t, l)

	l.mu.Lock()
	_, hasKey := l.byKey["8.8.8.8\x00bob"]
	ipFail := 0
	if st := l.byIP["8.8.8.8"]; st != nil {
		ipFail = st.failures
	}
	l.mu.Unlock()
	if hasKey {
		t.Fatal("identity key should be cleared")
	}
	if ipFail != 0 {
		t.Fatalf("IP failures=%d want 0 after clearing only contributor", ipFail)
	}
	// Full free budget restored.
	for i := 0; i < freeAttempts; i++ {
		if !l.reserve("8.8.8.8", "bob") {
			t.Fatalf("expected free budget at %d", i)
		}
	}
	if l.reserve("8.8.8.8", "bob") {
		t.Fatal("budget exhausted")
	}
}

func TestAuthLimiterUsernameCasing(t *testing.T) {
	l := newAuthLimiter()
	for i := 0; i < freeAttempts; i++ {
		user := "Alice"
		if i%2 == 0 {
			user = "ALICE"
		}
		if !l.reserve("7.7.7.7", user) {
			t.Fatalf("reserve %d", i)
		}
		l.failed("7.7.7.7", user)
	}
	if l.reserve("7.7.7.7", "Alice") {
		t.Fatal("casing must share one bucket and lock out")
	}
	checkAgg(t, l)
}

func TestAuthLimiterActiveReservationsBlockPrune(t *testing.T) {
	l := newAuthLimiter()
	now := time.Now()
	l.clock = func() time.Time { return now }

	if !l.reserve("5.5.5.5", "hold") {
		t.Fatal("reserve")
	}
	l.mu.Lock()
	l.byIP["5.5.5.5"].seen = now.Add(-entryExpiry - time.Minute)
	l.byKey["5.5.5.5\x00hold"].seen = now.Add(-entryExpiry - time.Minute)
	l.pruned = now.Add(-entryExpiry - time.Minute)
	l.mu.Unlock()

	now = now.Add(time.Second)
	_ = l.reserve("5.5.5.6", "x")

	l.mu.Lock()
	_, ipOK := l.byIP["5.5.5.5"]
	_, keyOK := l.byKey["5.5.5.5\x00hold"]
	l.mu.Unlock()
	if !ipOK || !keyOK {
		t.Fatal("active reservation must not be pruned")
	}
	l.canceled("5.5.5.5", "hold")
	checkAgg(t, l)
}

func TestAuthLimiterActiveLockoutNotEvicted(t *testing.T) {
	l := newAuthLimiter()
	now := time.Unix(1_700_000_000, 0)
	l.clock = func() time.Time { return now }

	for i := 0; i < freeAttempts; i++ {
		if !l.reserve("4.4.4.4", "locked") {
			t.Fatal("reserve")
		}
		l.failed("4.4.4.4", "locked")
	}
	// Make seen old but lockout still active.
	l.mu.Lock()
	l.byIP["4.4.4.4"].seen = now.Add(-entryExpiry - time.Minute)
	l.byKey["4.4.4.4\x00locked"].seen = now.Add(-entryExpiry - time.Minute)
	l.pruned = time.Time{}
	l.mu.Unlock()

	// Force prune path via new reserve elsewhere.
	now = now.Add(time.Second)
	if !l.reserve("4.4.4.5", "other") {
		t.Fatal("other")
	}
	l.canceled("4.4.4.5", "other")

	l.mu.Lock()
	_, keyOK := l.byKey["4.4.4.4\x00locked"]
	_, ipOK := l.byIP["4.4.4.4"]
	l.mu.Unlock()
	if !keyOK || !ipOK {
		t.Fatal("active lockout must not be pruned for capacity/time")
	}
	checkAgg(t, l)
}

func TestAuthLimiterExpiredIdleRemoved(t *testing.T) {
	l := newAuthLimiter()
	now := time.Now()
	l.clock = func() time.Time { return now }

	if !l.reserve("6.6.6.6", "gone") {
		t.Fatal("reserve")
	}
	l.failed("6.6.6.6", "gone")

	l.mu.Lock()
	l.byIP["6.6.6.6"].seen = now.Add(-entryExpiry - time.Minute)
	l.byKey["6.6.6.6\x00gone"].seen = now.Add(-entryExpiry - time.Minute)
	l.pruned = time.Time{}
	l.mu.Unlock()

	now = now.Add(time.Second)
	_ = l.reserve("6.6.6.7", "z")

	l.mu.Lock()
	_, ipOK := l.byIP["6.6.6.6"]
	_, keyOK := l.byKey["6.6.6.6\x00gone"]
	l.mu.Unlock()
	if ipOK || keyOK {
		t.Fatal("expired idle entry not pruned")
	}
	checkAgg(t, l)
}

func TestAuthLimiterEmptyCanceledCleaned(t *testing.T) {
	l := newAuthLimiter()
	if !l.reserve("3.3.3.3", "tmp") {
		t.Fatal("reserve")
	}
	l.canceled("3.3.3.3", "tmp")
	checkAgg(t, l)
	l.mu.Lock()
	_, keyOK := l.byKey["3.3.3.3\x00tmp"]
	_, ipOK := l.byIP["3.3.3.3"]
	l.mu.Unlock()
	if keyOK || ipOK {
		t.Fatal("empty canceled state should be cleaned")
	}
}

func TestAuthLimiterLockoutUsesClock(t *testing.T) {
	l := newAuthLimiter()
	now := time.Unix(1_700_000_000, 0)
	l.clock = func() time.Time { return now }

	for i := 0; i < freeAttempts; i++ {
		if !l.reserve("1.1.1.1", "u") {
			t.Fatalf("early lock at %d", i)
		}
		l.failed("1.1.1.1", "u")
	}
	if l.reserve("1.1.1.1", "u") {
		t.Fatal("locked")
	}
	now = now.Add(lockoutMax + time.Second)
	if !l.reserve("1.1.1.1", "u") {
		t.Fatal("should unlock after lockout expires")
	}
	l.canceled("1.1.1.1", "u")
	checkAgg(t, l)
}

func TestAuthLimiterCapacityExistingIdentityContinues(t *testing.T) {
	l := newAuthLimiter()
	now := time.Now()
	l.clock = func() time.Time { return now }
	// Fill key map to capacity with non-empty, non-expired, non-prunable entries.
	l.mu.Lock()
	for i := 0; i < maxAuthKeyEntries-1; i++ {
		ip := fmt.Sprintf("10.%d.%d.1", i/256, i%256)
		key := ip + "\x00u"
		l.byIP[ip] = &attemptState{failures: 1, seen: now.Add(-time.Minute)}
		l.byKey[key] = &attemptState{failures: 1, seen: now.Add(-time.Minute)}
	}
	trackedIP := "192.0.2.50"
	trackedKey := trackedIP + "\x00tracked"
	l.byIP[trackedIP] = &attemptState{failures: 1, seen: now}
	l.byKey[trackedKey] = &attemptState{failures: 1, seen: now}
	if len(l.byKey) != maxAuthKeyEntries {
		t.Fatalf("setup key len=%d", len(l.byKey))
	}
	l.mu.Unlock()

	if !l.reserve(trackedIP, "tracked") {
		t.Fatal("existing identity must reserve at capacity")
	}
	l.canceled(trackedIP, "tracked")

	if !l.reserve("198.51.100.1", "newuser") {
		t.Fatal("new identity must replace oldest safe state at capacity")
	}
	l.canceled("198.51.100.1", "newuser")
	checkAgg(t, l)

	// Independent IP-map capacity: consistent IP+identity pairs so aggregates hold.
	l2 := newAuthLimiter()
	l2.clock = func() time.Time { return now }
	l2.mu.Lock()
	for i := 0; i < maxAuthIPEntries; i++ {
		ip := fmt.Sprintf("11.%d.%d.1", i/256, i%256)
		seen := now.Add(-time.Minute)
		if i == 0 {
			seen = now
		}
		l2.byIP[ip] = &attemptState{failures: 1, seen: seen}
		l2.byKey[ip+"\x00u"] = &attemptState{failures: 1, seen: seen}
	}
	existIP := "11.0.0.1"
	l2.mu.Unlock()

	if !l2.reserve(existIP, "u") {
		t.Fatal("existing IP+user at IP capacity should still reserve")
	}
	l2.canceled(existIP, "u")
	if !l2.reserve("203.0.113.9", "x") {
		t.Fatal("new IP must replace oldest safe IP at capacity")
	}
	l2.canceled("203.0.113.9", "x")
	l2.mu.Lock()
	if len(l2.byIP) > maxAuthIPEntries || len(l2.byKey) > maxAuthKeyEntries {
		t.Fatalf("overshoot ips=%d keys=%d", len(l2.byIP), len(l2.byKey))
	}
	l2.mu.Unlock()
	checkAgg(t, l2)
}

func TestAuthLimiterCapacityNoTemporaryOvershoot(t *testing.T) {
	l := newAuthLimiter()
	now := time.Now()
	l.clock = func() time.Time { return now }
	l.mu.Lock()
	for i := 0; i < maxAuthKeyEntries; i++ {
		ip := fmt.Sprintf("12.%d.%d.1", i/256, i%256)
		l.byIP[ip] = &attemptState{failures: 1, seen: now}
		l.byKey[ip+"\x00u"] = &attemptState{failures: 1, seen: now}
	}
	l.mu.Unlock()
	if !l.reserve("203.0.113.50", "overflow") {
		t.Fatal("safe capacity entry was not replaced")
	}
	l.mu.Lock()
	if len(l.byKey) > maxAuthKeyEntries || len(l.byIP) > maxAuthIPEntries {
		t.Fatalf("overshoot keys=%d ips=%d", len(l.byKey), len(l.byIP))
	}
	l.mu.Unlock()
	l.canceled("203.0.113.50", "overflow")
}

func TestAuthLimiterFailedDoesNotHalfReserve(t *testing.T) {
	l := newAuthLimiter()
	if !l.reserve("10.0.0.9", "half") {
		t.Fatal("reserve")
	}
	l.failed("10.0.0.9", "half")
	checkAgg(t, l)
	// Mismatched terminal without reservation must not create half state.
	l.failed("10.0.0.9", "never-reserved")
	checkAgg(t, l)
	l.mu.Lock()
	_, ghost := l.byKey["10.0.0.9\x00never-reserved"]
	l.mu.Unlock()
	if ghost {
		t.Fatal("mismatched fail must not create identity half-entry")
	}
}

func TestAuthLimiterConcurrentSuccessFailureNoNegatives(t *testing.T) {
	l := newAuthLimiter()
	for i := 0; i < 3; i++ {
		if !l.reserve("15.15.15.15", "alice") {
			t.Fatal("seed")
		}
		l.failed("15.15.15.15", "alice")
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if i%2 == 0 {
				if l.reserve("15.15.15.15", "alice") {
					l.succeeded("15.15.15.15", "alice")
				}
			} else {
				if l.reserve("15.15.15.15", "alice") {
					l.failed("15.15.15.15", "alice")
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()
	checkAgg(t, l)
}

func TestAuthLimiterCanceledNoFailureEffect(t *testing.T) {
	l := newAuthLimiter()
	if !l.reserve("16.16.16.16", "c") {
		t.Fatal("reserve")
	}
	l.canceled("16.16.16.16", "c")
	l.mu.Lock()
	fail := 0
	if st := l.byIP["16.16.16.16"]; st != nil {
		fail = st.failures
	}
	l.mu.Unlock()
	if fail != 0 {
		t.Fatalf("cancel changed failures to %d", fail)
	}
	checkAgg(t, l)
}

func TestAuthLimiterConcurrentCapacityBoundary(t *testing.T) {
	l := newAuthLimiter()
	// Leave room for N concurrent new identities near empty.
	const n = 50
	start := make(chan struct{})
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if l.reserve(fmt.Sprintf("20.0.0.%d", i+1), fmt.Sprintf("u%d", i)) {
				ok.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if ok.Load() != int32(n) {
		t.Fatalf("ok=%d want %d", ok.Load(), n)
	}
	l.mu.Lock()
	if len(l.byKey) > maxAuthKeyEntries || len(l.byIP) > maxAuthIPEntries {
		t.Fatalf("capacity exceeded keys=%d ips=%d", len(l.byKey), len(l.byIP))
	}
	if err := l.assertAggregatesLocked(); err != nil {
		l.mu.Unlock()
		t.Fatal(err)
	}
	l.mu.Unlock()
}

func TestAuthLimiterUsernameGlobalConcurrentBudget(t *testing.T) {
	l := newAuthLimiter()
	for i := 0; i < freeAttempts; i++ {
		if !l.reserve(fmt.Sprintf("192.0.2.%d", i+1), "DistributedUser") {
			t.Fatalf("distributed reserve %d", i)
		}
	}
	if l.reserve("198.51.100.1", "distributeduser") {
		t.Fatal("username-global in-flight budget must reject another IP")
	}
	for i := 0; i < freeAttempts; i++ {
		l.failed(fmt.Sprintf("192.0.2.%d", i+1), "DistributedUser")
	}
	if !l.reserve("198.51.100.1", "distributeduser") {
		t.Fatal("completed distributed failures must not persistently lock the username")
	}
	l.canceled("198.51.100.1", "distributeduser")
	checkAgg(t, l)
}

func TestAuthWorkQueueSaturated(t *testing.T) {
	s := &Server{
		hashing:   make(chan struct{}, 1),
		authLimit: newAuthLimiter(),
	}
	s.hashing <- struct{}{}
	if s.acquireHashSlot() {
		t.Fatal("saturated hashing must reject without waiting")
	}
	if len(s.authLimit.byIP) != 0 || len(s.authLimit.byKey) != 0 || len(s.authLimit.byUser) != 0 {
		t.Fatal("busy hash admission must not reserve or charge an auth identity")
	}
}

func TestAuthLimiterCapacityEvictsOldestSafeState(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newAuthLimiterSized(2, 2, entryExpiry, entryExpiry)
	l.clock = func() time.Time { return now }
	for _, tc := range []struct {
		ip   string
		seen time.Time
	}{{"192.0.2.1", now.Add(-time.Minute)}, {"192.0.2.2", now}} {
		l.mu.Lock()
		l.byIP[tc.ip] = &attemptState{failures: 1, seen: tc.seen}
		l.byKey[tc.ip+"\x00user"] = &attemptState{failures: 1, seen: tc.seen}
		l.mu.Unlock()
	}

	if !l.reserve("192.0.2.3", "user") {
		t.Fatal("new identity was denied despite safe capacity state")
	}
	l.mu.Lock()
	_, oldestIP := l.byIP["192.0.2.1"]
	_, oldestKey := l.byKey["192.0.2.1\x00user"]
	_, newerIP := l.byIP["192.0.2.2"]
	l.mu.Unlock()
	if oldestIP || oldestKey || !newerIP {
		t.Fatalf("oldestIP=%v oldestKey=%v newerIP=%v", oldestIP, oldestKey, newerIP)
	}
	l.canceled("192.0.2.3", "user")
	checkAgg(t, l)
}

func TestAuthLimiterExistingNoFullSweep(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newAuthLimiterSized(100, 100, entryExpiry, entryExpiry)
	l.clock = func() time.Time { return now }
	if !l.reserve("1.1.1.1", "alice") {
		t.Fatal("seed")
	}
	l.canceled("1.1.1.1", "alice")
	// Mark a failure so empty cleanup doesn't delete, and so next reserve is existing.
	if !l.reserve("1.1.1.1", "alice") {
		t.Fatal("re-seed")
	}
	l.failed("1.1.1.1", "alice")
	l.mu.Lock()
	before := l.fullSweeps
	l.pruned = now // periodic prune not due
	l.mu.Unlock()
	if !l.reserve("1.1.1.1", "alice") {
		t.Fatal("existing reserve")
	}
	l.canceled("1.1.1.1", "alice")
	l.mu.Lock()
	after := l.fullSweeps
	l.mu.Unlock()
	if after != before {
		t.Fatalf("existing identity reserve triggered sweeps %d -> %d", before, after)
	}
	checkAgg(t, l)
}

func TestAuthLimiterNewBelowCapacityNoFullSweep(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newAuthLimiterSized(100, 100, entryExpiry, entryExpiry)
	l.clock = func() time.Time { return now }
	l.mu.Lock()
	l.pruned = now
	before := l.fullSweeps
	l.mu.Unlock()
	if !l.reserve("2.2.2.2", "new") {
		t.Fatal("new below cap")
	}
	l.canceled("2.2.2.2", "new")
	l.mu.Lock()
	after := l.fullSweeps
	l.mu.Unlock()
	if after != before {
		t.Fatalf("new below capacity triggered sweeps %d -> %d", before, after)
	}
	checkAgg(t, l)
}

func TestAuthLimiterCapacitySweepOnceThenReject(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const capN = 8
	l := newAuthLimiterSized(capN, capN, entryExpiry, entryExpiry)
	l.clock = func() time.Time { return now }
	for i := 0; i < capN; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		if !l.reserve(ip, "u") {
			t.Fatalf("fill %d", i)
		}
		l.failed(ip, "u")
	}
	l.mu.Lock()
	before := l.fullSweeps
	l.pruned = now
	for ip, st := range l.byIP {
		if ip != "10.0.0.1" {
			st.seen = now.Add(-time.Minute)
		}
	}
	for key, st := range l.byKey {
		if key != "10.0.0.1\x00u" {
			st.seen = now.Add(-time.Minute)
		}
	}
	l.mu.Unlock()

	// First at-capacity new identity sweeps and replaces safe oldest state.
	if !l.reserve("203.0.113.1", "attacker0") {
		t.Fatal("expected oldest safe state replacement")
	}
	l.failed("203.0.113.1", "attacker0")
	l.mu.Lock()
	mid := l.fullSweeps
	l.mu.Unlock()
	if mid != before+1 {
		t.Fatalf("first capacity replacement sweeps=%d want %d", mid-before, 1)
	}
	// Hundreds more at same logical time: no additional full sweeps.
	for i := 0; i < 300; i++ {
		if l.reserve(fmt.Sprintf("198.51.100.%d", i%250+1), fmt.Sprintf("a%d", i)) {
			t.Fatalf("unexpected accept at %d", i)
		}
	}
	l.mu.Lock()
	after := l.fullSweeps
	l.mu.Unlock()
	if after != mid {
		t.Fatalf("repeated capacity rejects swept %d more times", after-mid)
	}
	// Existing identity still usable.
	if !l.reserve("10.0.0.1", "u") {
		t.Fatal("existing must remain usable at capacity")
	}
	l.canceled("10.0.0.1", "u")
	checkAgg(t, l)
}

func TestAuthLimiterCapacityReclaimsExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const capN = 4
	l := newAuthLimiterSized(capN, capN, entryExpiry, entryExpiry)
	l.clock = func() time.Time { return now }
	for i := 0; i < capN; i++ {
		ip := fmt.Sprintf("10.1.0.%d", i+1)
		if !l.reserve(ip, "u") {
			t.Fatal("fill")
		}
		l.failed(ip, "u")
	}
	// Make all expired idle.
	l.mu.Lock()
	for _, st := range l.byIP {
		st.seen = now.Add(-entryExpiry - time.Minute)
	}
	for _, st := range l.byKey {
		st.seen = now.Add(-entryExpiry - time.Minute)
	}
	l.pruned = now
	l.mu.Unlock()
	now = now.Add(time.Second)
	if !l.reserve("203.0.113.50", "fresh") {
		t.Fatal("capacity sweep should reclaim expired idle")
	}
	l.canceled("203.0.113.50", "fresh")
	checkAgg(t, l)
}

func TestAuthLimiterCapacityFloodRealClockBoundedSweeps(t *testing.T) {
	const capN = 16
	l := newAuthLimiterSized(capN, capN, entryExpiry, entryExpiry)
	// Fill both maps with non-prunable (recent failure) entries.
	for i := 0; i < capN; i++ {
		ip := fmt.Sprintf("10.50.0.%d", i+1)
		if !l.reserve(ip, "u") {
			t.Fatalf("fill %d", i)
		}
		l.failed(ip, "u")
	}
	l.mu.Lock()
	l.pruned = l.nowTime() // prevent periodic prune
	before := l.fullSweeps
	l.mu.Unlock()

	l.clock = time.Now
	const flood = 2000
	accepted := 0
	for i := 0; i < flood; i++ {
		if l.reserve(fmt.Sprintf("198.51.100.%d", i%250+1), fmt.Sprintf("flood%d", i)) {
			accepted++
			l.failed(fmt.Sprintf("198.51.100.%d", i%250+1), fmt.Sprintf("flood%d", i))
		}
	}
	if accepted > 1 {
		t.Fatalf("accepted %d replacements within one sweep interval", accepted)
	}
	l.mu.Lock()
	grew := l.fullSweeps - before
	l.mu.Unlock()
	if grew > 2 {
		t.Fatalf("fullSweeps grew by %d, want at most 2 under real-clock flood", grew)
	}
	checkAgg(t, l)
}

func TestAuthLimiterExistingDuringCapacityFlood(t *testing.T) {
	const capN = 16
	l := newAuthLimiterSized(capN, capN, entryExpiry, entryExpiry)
	for i := 0; i < capN; i++ {
		ip := fmt.Sprintf("10.51.0.%d", i+1)
		if !l.reserve(ip, "u") {
			t.Fatalf("fill %d", i)
		}
		l.failed(ip, "u")
	}
	l.mu.Lock()
	for ip, st := range l.byIP {
		if ip == "10.51.0.1" {
			st.seen = time.Now()
		} else {
			st.seen = time.Now().Add(-time.Minute)
		}
	}
	for key, st := range l.byKey {
		if key == "10.51.0.1\x00u" {
			st.seen = time.Now()
		} else {
			st.seen = time.Now().Add(-time.Minute)
		}
	}
	l.pruned = l.nowTime()
	l.mu.Unlock()
	l.clock = time.Now

	for i := 0; i < 500; i++ {
		if l.reserve(fmt.Sprintf("203.0.113.%d", i%200+1), fmt.Sprintf("n%d", i)) {
			l.failed(fmt.Sprintf("203.0.113.%d", i%200+1), fmt.Sprintf("n%d", i))
		}
		// Existing seat still reservable during the flood.
		if !l.reserve("10.51.0.1", "u") {
			t.Fatalf("existing rejected during flood i=%d", i)
		}
		l.canceled("10.51.0.1", "u")
	}
	checkAgg(t, l)
}

func TestAuthLimiterSmallCapacityConcurrentExact(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const capN = 10
	const remaining = 3
	l := newAuthLimiterSized(capN, capN, entryExpiry, entryExpiry)
	l.clock = func() time.Time { return now }
	for i := 0; i < capN-remaining; i++ {
		ip := fmt.Sprintf("10.2.0.%d", i+1)
		if !l.reserve(ip, "u") {
			t.Fatal("prefill")
		}
		l.failed(ip, "u")
	}
	const attempts = 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if l.reserve(fmt.Sprintf("10.9.0.%d", i+1), "n") {
				ok.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if got := ok.Load(); got != int32(remaining+1) {
		t.Fatalf("accepted=%d want %d (free slots plus one safe replacement)", got, remaining+1)
	}
	l.mu.Lock()
	if len(l.byIP) > capN || len(l.byKey) > capN {
		t.Fatalf("over capacity ips=%d keys=%d", len(l.byIP), len(l.byKey))
	}
	// No half-created: every key IP has matching IP entry packages.
	for k := range l.byKey {
		ip := ipFromKey(k)
		if _, ok := l.byIP[ip]; !ok {
			l.mu.Unlock()
			t.Fatalf("half-created identity without IP %q", k)
		}
	}
	if err := l.assertAggregatesLocked(); err != nil {
		l.mu.Unlock()
		t.Fatal(err)
	}
	l.mu.Unlock()
}

func TestAuthLimiterSuccessRemovesEmptyDirectly(t *testing.T) {
	l := newAuthLimiter()
	if !l.reserve("30.30.30.30", "s") {
		t.Fatal("reserve")
	}
	l.succeeded("30.30.30.30", "s")
	l.mu.Lock()
	_, k := l.byKey["30.30.30.30\x00s"]
	_, ip := l.byIP["30.30.30.30"]
	l.mu.Unlock()
	if k || ip {
		t.Fatal("success should drop empty identity and IP directly")
	}
	checkAgg(t, l)
}

func TestAuthLimiterPeriodicPruneOnlyWhenDue(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newAuthLimiterSized(50, 50, entryExpiry, entryExpiry)
	l.clock = func() time.Time { return now }
	if !l.reserve("40.40.40.40", "p") {
		t.Fatal("reserve")
	}
	l.failed("40.40.40.40", "p")
	l.mu.Lock()
	l.byIP["40.40.40.40"].seen = now.Add(-entryExpiry - time.Minute)
	l.byKey["40.40.40.40\x00p"].seen = now.Add(-entryExpiry - time.Minute)
	l.pruned = now // not due
	before := l.fullSweeps
	l.mu.Unlock()
	// New reserve remote: periodic not due, capacity not hit → no sweep, stale remains.
	if !l.reserve("40.40.40.41", "q") {
		t.Fatal("other")
	}
	l.canceled("40.40.40.41", "q")
	l.mu.Lock()
	_, still := l.byKey["40.40.40.40\x00p"]
	mid := l.fullSweeps
	l.mu.Unlock()
	if !still {
		t.Fatal("periodic prune must not run before interval")
	}
	if mid != before {
		t.Fatalf("unexpected sweep")
	}
	// Advance past interval on next reserve.
	now = now.Add(entryExpiry + time.Second)
	if !l.reserve("40.40.40.42", "r") {
		t.Fatal("r")
	}
	l.canceled("40.40.40.42", "r")
	l.mu.Lock()
	_, gone := l.byKey["40.40.40.40\x00p"]
	l.mu.Unlock()
	if gone {
		t.Fatal("expired idle should be pruned when interval elapses")
	}
	checkAgg(t, l)
}
