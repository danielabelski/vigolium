package http

import (
	"net/http"
	"testing"

	"github.com/vigolium/vigolium/pkg/types"
)

// transportOf digs the shared *http.Transport out of a Requester so a test can
// assert how the idle-connection pool was sized.
func transportOf(t *testing.T, r *Requester) *http.Transport {
	t.Helper()
	tr, ok := r.client.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", r.client.HTTPClient.Transport)
	}
	return tr
}

// idlePoolOpts builds default options with explicit per-host concurrency bounds.
func idlePoolOpts(maxPerHost, ceiling int) *types.Options {
	opts := types.DefaultOptions()
	opts.MaxPerHost = maxPerHost
	opts.MaxPerHostCeiling = ceiling
	return opts
}

// The idle pool must be sized to the concurrency the per-host limiter can
// actually REACH. The adaptive limiter ramps a healthy host above MaxPerHost, and
// a pool sized to the starting value would close every connection past it on
// return — manufacturing a fresh TCP+TLS handshake at exactly the concurrency the
// ramp unlocked.
func TestIdlePoolSizedFromCeiling(t *testing.T) {
	tr := transportOf(t, newTestRequesterWithOpts(t, idlePoolOpts(40, 80)))

	if tr.MaxIdleConnsPerHost != 80 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 80 (the ramp ceiling)", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxIdleConns != 800 {
		t.Errorf("MaxIdleConns = %d, want 800 (10x per-host)", tr.MaxIdleConns)
	}
}

// With no ceiling published (limiter can't ramp) the pool keeps its previous
// MaxPerHost sizing — this change must not move the static-mode default.
func TestIdlePoolFallsBackToMaxPerHost(t *testing.T) {
	tr := transportOf(t, newTestRequesterWithOpts(t, idlePoolOpts(40, 0)))

	if tr.MaxIdleConnsPerHost != 40 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 40 (MaxPerHost, no ceiling set)", tr.MaxIdleConnsPerHost)
	}
}

// A ceiling below MaxPerHost must never shrink the pool below the concurrency
// that is actually in use.
func TestIdlePoolNeverBelowMaxPerHost(t *testing.T) {
	tr := transportOf(t, newTestRequesterWithOpts(t, idlePoolOpts(40, 5)))

	if tr.MaxIdleConnsPerHost != 40 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 40 (floored at MaxPerHost)", tr.MaxIdleConnsPerHost)
	}
}

// The 256 cap still bounds file descriptors when a pathological ceiling is
// configured.
func TestIdlePoolCappedAt256(t *testing.T) {
	tr := transportOf(t, newTestRequesterWithOpts(t, idlePoolOpts(200, 4000)))

	if tr.MaxIdleConnsPerHost != 256 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 256 (hard cap)", tr.MaxIdleConnsPerHost)
	}
}
