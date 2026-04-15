package web

import (
	"testing"
	"time"
)

// Verifies the per-UID exponential backoff schedule and that recordSuccess
// fully clears the entry. Added after the v1.11.x design discussion that
// flagged unrate-limited HMAC attempts as a P0 hardening gap.
func TestTunnelRateLimiter_BackoffDoubles(t *testing.T) {
	l := &tunnelRateLimiter{entries: map[string]*tunnelRateEntry{}}

	uid := "lss-test"

	// First failure: ~1s lockout.
	l.recordFailure(uid)
	if ok, retry := l.allow(uid); ok {
		t.Fatalf("expected blocked after 1 failure, got allow=true")
	} else if retry > 2*time.Second || retry < 500*time.Millisecond {
		t.Fatalf("expected retry ~1s after first failure, got %v", retry)
	}

	// Force "time has passed" and try second failure.
	l.entries[uid].blockedUntil = time.Now().Add(-time.Second)
	if ok, _ := l.allow(uid); !ok {
		t.Fatal("expected allow once lockout expires")
	}
	l.recordFailure(uid)
	if ok, retry := l.allow(uid); ok {
		t.Fatal("expected blocked after 2nd failure")
	} else if retry > 3*time.Second || retry < time.Second {
		t.Fatalf("expected retry ~2s after second failure, got %v", retry)
	}

	// Two more failures should keep doubling (4s, 8s).
	l.entries[uid].blockedUntil = time.Now().Add(-time.Second)
	l.recordFailure(uid)
	l.entries[uid].blockedUntil = time.Now().Add(-time.Second)
	l.recordFailure(uid)
	if _, retry := l.allow(uid); retry < 6*time.Second || retry > 10*time.Second {
		t.Fatalf("expected retry ~8s after 4 failures, got %v", retry)
	}
}

func TestTunnelRateLimiter_LockoutCappedAtMax(t *testing.T) {
	l := &tunnelRateLimiter{entries: map[string]*tunnelRateEntry{}}
	uid := "lss-overflow"
	for i := 0; i < 30; i++ {
		l.recordFailure(uid)
		l.entries[uid].blockedUntil = time.Now().Add(-time.Second)
	}
	l.recordFailure(uid)
	_, retry := l.allow(uid)
	if retry > tunnelRateMaxLockout+time.Second {
		t.Fatalf("lockout %v exceeded ceiling %v", retry, tunnelRateMaxLockout)
	}
}

func TestTunnelRateLimiter_SuccessClears(t *testing.T) {
	l := &tunnelRateLimiter{entries: map[string]*tunnelRateEntry{}}
	uid := "lss-cleared"
	l.recordFailure(uid)
	l.recordFailure(uid)
	l.recordSuccess(uid)
	if ok, _ := l.allow(uid); !ok {
		t.Fatal("recordSuccess should clear the lockout entirely")
	}
}

func TestTunnelRateLimiter_SeparateUIDs(t *testing.T) {
	l := &tunnelRateLimiter{entries: map[string]*tunnelRateEntry{}}
	l.recordFailure("uid-a")
	if ok, _ := l.allow("uid-b"); !ok {
		t.Fatal("failure on uid-a must not block uid-b")
	}
}
