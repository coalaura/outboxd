package smtpd

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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

	// failures still freeAttempts-1; cancel did not reset and did not add a failure
	if !l.reserve("1.2.3.4", "u") {
		t.Fatal("expected reserve after cancel")
	}
	l.failed("1.2.3.4", "u")
	// failures == freeAttempts → locked
	if l.reserve("1.2.3.4", "u") {
		t.Fatal("expected lockout")
	}
}

func TestAuthLimiterSuccessClearsOnlyIdentity(t *testing.T) {
	l := newAuthLimiter()
	for i := 0; i < 3; i++ {
		if !l.reserve("9.9.9.9", "other") {
			t.Fatal("reserve other")
		}
		l.failed("9.9.9.9", "other")
	}
	if !l.reserve("9.9.9.9", "alice") {
		t.Fatal("reserve alice")
	}
	l.succeeded("9.9.9.9", "alice")

	l.mu.Lock()
	ipFail := 0
	if st := l.byIP["9.9.9.9"]; st != nil {
		ipFail = st.failures
	}
	_, aliceKey := l.byKey["9.9.9.9\x00alice"]
	l.mu.Unlock()
	if ipFail != 3 {
		t.Fatalf("IP failures cleared by unrelated success: got %d", ipFail)
	}
	if aliceKey {
		t.Fatal("alice key should be removed after success with no in-flight")
	}
}

func TestAuthLimiterSuccessClearsIdentityState(t *testing.T) {
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

	// Identity failures cleared; byKey entry gone. IP failures remain (from this user),
	// so remaining free budget is freeAttempts - 2.
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
	if ipFail != 2 {
		t.Fatalf("IP failures=%d want 2 (success must not wipe IP budget casually used by other users)", ipFail)
	}
	// Remaining budget on IP: freeAttempts - 2
	for i := 0; i < freeAttempts-2; i++ {
		if !l.reserve("8.8.8.8", "bob") {
			t.Fatalf("expected remaining budget at %d", i)
		}
	}
	if l.reserve("8.8.8.8", "bob") {
		t.Fatal("IP budget still enforces freeAttempts across usernames")
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
	l.mu.Unlock()
	if ipOK {
		t.Fatal("expired idle entry not pruned")
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
