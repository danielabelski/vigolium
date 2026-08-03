package http

import (
	"net/http"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/types"
)

// idlePoolTransport builds a Requester whose per-host limiter is configured with
// the given bounds, and returns its shared transport. A nil limiter is expressed
// by maxPerHost <= 0.
func idlePoolTransport(t *testing.T, maxPerHost, ceiling int, adaptive bool) *http.Transport {
	t.Helper()

	opts := types.DefaultOptions()
	opts.MaxPerHost = maxPerHost
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}

	svc := &services.Services{Options: opts}
	if maxPerHost > 0 {
		limiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
			MaxPerHost:     maxPerHost,
			CeilingPerHost: ceiling,
			Adaptive:       adaptive,
			EvictInterval:  time.Hour,
		})
		t.Cleanup(func() { _ = limiter.Close() })
		svc.HostLimiter = limiter
	}

	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	tr, ok := r.client.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", r.client.HTTPClient.Transport)
	}
	return tr
}

// The idle pool must be sized to the concurrency the per-host limiter can
// actually REACH. The adaptive limiter ramps a healthy host above MaxPerHost, and
// a pool sized to the starting value would close every connection past it on
// return — manufacturing a fresh TCP+TLS handshake at exactly the concurrency the
// ramp unlocked.
func TestIdlePoolSizing(t *testing.T) {
	tests := []struct {
		name        string
		maxPerHost  int
		ceiling     int
		adaptive    bool
		wantPerHost int
	}{
		// Adaptive ramps to 2x, so the pool must cover 80 rather than 40.
		{"adaptive ramp headroom", 40, 0, true, 80},
		// Non-adaptive can never exceed MaxPerHost: unchanged from before.
		{"static pins to max", 40, 0, false, 40},
		{"explicit ceiling honored", 40, 100, true, 100},
		// A ceiling below MaxPerHost must never shrink the pool below the
		// concurrency actually in use.
		{"ceiling below max is floored", 40, 5, true, 40},
		// The hard cap still bounds file descriptors.
		{"capped at 256", 200, 4000, true, 256},
		// No limiter at all falls back to MaxPerHost.
		{"no limiter falls back", 0, 0, false, 10},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := idlePoolTransport(t, tc.maxPerHost, tc.ceiling, tc.adaptive)
			if tr.MaxIdleConnsPerHost != tc.wantPerHost {
				t.Errorf("MaxIdleConnsPerHost = %d, want %d", tr.MaxIdleConnsPerHost, tc.wantPerHost)
			}
			if want := tc.wantPerHost * 10; tr.MaxIdleConns != want {
				t.Errorf("MaxIdleConns = %d, want %d (10x per-host)", tr.MaxIdleConns, want)
			}
		})
	}
}
