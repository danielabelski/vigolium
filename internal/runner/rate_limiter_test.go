package runner

import (
	"testing"

	"golang.org/x/time/rate"
)

// TestBuildScanRateLimiter verifies the opt-in gating: no limiter is built unless
// an explicit positive rate is set, so default scans keep their current
// throughput; a positive rate yields a token bucket at that rate.
func TestBuildScanRateLimiter(t *testing.T) {
	if l := buildScanRateLimiter(0); l != nil {
		t.Errorf("rate 0 must yield no limiter (unlimited), got %v", l)
	}
	if l := buildScanRateLimiter(-5); l != nil {
		t.Errorf("negative rate must yield no limiter, got %v", l)
	}

	l := buildScanRateLimiter(10)
	if l == nil {
		t.Fatal("rate 10 must yield a limiter")
	}
	if got := l.Limit(); got != rate.Limit(10) {
		t.Errorf("limiter rate = %v, want 10", got)
	}
	if got := l.Burst(); got != 10 {
		t.Errorf("limiter burst = %d, want 10", got)
	}
}
