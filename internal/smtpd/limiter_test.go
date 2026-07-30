package smtpd

import (
	"context"
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
		l.byIP[ip] = &attemptState{failures: 1, seen: now}
		l.byKey[key] = &attemptState{failures: 1, seen: now}
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

	if l.reserve("198.51.100.1", "newuser") {
		t.Fatal("new identity must be rejected when key map at capacity")
	}
	checkAgg(t, l)

	// Independent IP-map capacity: consistent IP+identity pairs so aggregates hold.
	l2 := newAuthLimiter()
	l2.clock = func() time.Time { return now }
	l2.mu.Lock()
	for i := 0; i < maxAuthIPEntries; i++ {
		ip := fmt.Sprintf("11.%d.%d.1", i/256, i%256)
		l2.byIP[ip] = &attemptState{failures: 1, seen: now}
		l2.byKey[ip+"\x00u"] = &attemptState{failures: 1, seen: now}
	}
	existIP := "11.0.0.1"
	l2.mu.Unlock()

	if !l2.reserve(existIP, "u") {
		t.Fatal("existing IP+user at IP capacity should still reserve")
	}
	l2.canceled(existIP, "u")
	if l2.reserve("203.0.113.9", "x") {
		t.Fatal("new IP must be rejected at IP capacity")
	}
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
	if l.reserve("203.0.113.50", "overflow") {
		t.Fatal("must not create beyond capacity")
	}
	l.mu.Lock()
	if len(l.byKey) > maxAuthKeyEntries || len(l.byIP) > maxAuthIPEntries {
		t.Fatalf("overshoot keys=%d ips=%d", len(l.byKey), len(l.byIP))
	}
	l.mu.Unlock()
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
			if l.reserve(fmt.Sprintf("20.0.0.%d", i+1), "u") {
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

func TestAuthWorkQueueSaturated(t *testing.T) {
	s := &Server{
		hashing:  make(chan struct{}, 1),
		authWait: make(chan struct{}, 1),
	}
	s.hashing <- struct{}{}
	s.authWait <- struct{}{}
	err := s.acquireHashSlot(context.Background())
	if err != errAuthBusy {
		t.Fatalf("want errAuthBusy, got %v", err)
	}
}
