package web

import (
	"sync"
	"time"
)

// tunnelRateLimiter throttles repeated failed auth attempts on the
// /ws/ssh-tunnel endpoint. A leaked node PSK without this would let an
// attacker brute the HMAC space at line rate.
//
// Algorithm: per-UID exponential backoff. Each failed auth doubles the lockout
// up to a 10-minute ceiling. A successful auth clears the entry. A janitor
// reaps stale entries hourly.
type tunnelRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*tunnelRateEntry
}

type tunnelRateEntry struct {
	failCount    int
	blockedUntil time.Time
	lastSeen     time.Time
}

const (
	tunnelRateBaseLockout = 1 * time.Second  // doubles per failure: 1s, 2s, 4s, 8s, …
	tunnelRateMaxLockout  = 10 * time.Minute // hard ceiling
	tunnelRateReapAge     = 1 * time.Hour    // entries idle longer than this are forgotten
)

var (
	tunnelLimiter     *tunnelRateLimiter
	tunnelLimiterOnce sync.Once
)

func getTunnelLimiter() *tunnelRateLimiter {
	tunnelLimiterOnce.Do(func() {
		tunnelLimiter = &tunnelRateLimiter{entries: make(map[string]*tunnelRateEntry)}
		go tunnelLimiter.janitor()
	})
	return tunnelLimiter
}

// allow returns (true, 0) if the UID may attempt auth now, or (false, retryAfter)
// otherwise. The retryAfter duration is what to put in the Retry-After header.
func (l *tunnelRateLimiter) allow(uid string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[uid]
	if e == nil {
		return true, 0
	}
	now := time.Now()
	e.lastSeen = now
	if now.Before(e.blockedUntil) {
		return false, e.blockedUntil.Sub(now)
	}
	return true, 0
}

func (l *tunnelRateLimiter) recordFailure(uid string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[uid]
	if e == nil {
		e = &tunnelRateEntry{}
		l.entries[uid] = e
	}
	e.failCount++
	lockout := tunnelRateBaseLockout << (e.failCount - 1)
	if lockout <= 0 || lockout > tunnelRateMaxLockout {
		lockout = tunnelRateMaxLockout
	}
	e.blockedUntil = time.Now().Add(lockout)
	e.lastSeen = time.Now()
}

func (l *tunnelRateLimiter) recordSuccess(uid string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, uid)
}

func (l *tunnelRateLimiter) janitor() {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-tunnelRateReapAge)
		l.mu.Lock()
		for uid, e := range l.entries {
			if e.lastSeen.Before(cutoff) && time.Now().After(e.blockedUntil) {
				delete(l.entries, uid)
			}
		}
		l.mu.Unlock()
	}
}
