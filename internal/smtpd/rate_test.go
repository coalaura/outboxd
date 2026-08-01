package smtpd

import (
	"testing"
	"time"
)

func TestSubmissionLimiterBurstNotFullHourly(t *testing.T) {
	// hourly 60 → default burst would be 1 if burstDefault; inject msgBurst=5 with hourly 1000
	l := newSubmissionLimiter(1000, 10000, 5, 50)

	// Only burst of 5 messages immediately, not 1000.
	for i := range 5 {
		if !l.take("u", 1) {
			t.Fatalf("take %d failed", i)
		}
	}

	if l.take("u", 1) {
		t.Fatal("6th take should fail — burst exhausted")
	}
}

func TestSubmissionLimiterRefill(t *testing.T) {
	l := newSubmissionLimiter(3600, 3600, 2, 2) // 1 token/sec rate effective for pratical test
	if !l.take("u", 1) {
		t.Fatal("first")
	}

	if !l.take("u", 1) {
		t.Fatal("second")
	}

	if l.take("u", 1) {
		t.Fatal("burst empty")
	}

	// Manually age the allowance
	l.mu.Lock()
	a := l.entries["u"]
	a.updated = time.Now().Add(-2 * time.Second)
	l.mu.Unlock()

	if !l.take("u", 1) {
		t.Fatal("expected refill after 2s at 3600/hour (~1/s)")
	}
}

func TestSubmissionLimiterEntryExpiry(t *testing.T) {
	l := newSubmissionLimiter(10, 10, 2, 2)
	if !l.take("gone", 1) {
		t.Fatal("take")
	}

	l.mu.Lock()
	l.entries["gone"].seen = time.Now().Add(-entryExpiry - time.Minute)
	l.pruned = time.Now().Add(-entryExpiry - time.Minute)
	l.mu.Unlock()

	// force prune via another take after expiry interval
	if !l.take("other", 1) {
		t.Fatal("other")
	}

	l.mu.Lock()
	_, still := l.entries["gone"]
	l.mu.Unlock()

	if still {
		t.Fatal("expired entry not pruned")
	}
}
