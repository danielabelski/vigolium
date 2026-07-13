package ratelimit

import "testing"

// TestAddEvictNotifierFansOut verifies the evict registry notifies every
// registered subscriber, not just the last (which the old single-field setter
// did), and that a nil sink is inert (CR-07).
func TestAddEvictNotifierFansOut(t *testing.T) {
	h := NewHostRateLimiter(HostRateLimiterConfig{})
	defer func() { _ = h.Close() }()

	var a, b int
	h.AddEvictNotifier(func(string) { a++ })
	h.AddEvictNotifier(func(string) { b++ })
	h.AddEvictNotifier(nil) // ignored, must not panic

	h.notifyEvict("example.com")
	if a != 1 || b != 1 {
		t.Fatalf("both subscribers should fire once: a=%d b=%d (last-writer would drop one)", a, b)
	}

	h.notifyEvict("example.com")
	if a != 2 || b != 2 {
		t.Fatalf("both subscribers should fire again: a=%d b=%d", a, b)
	}
}
