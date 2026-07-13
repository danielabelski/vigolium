package crawler

import (
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/fragment"
)

// TestBuildResultStampsEndTime verifies the crawl Result carries a valid,
// non-negative duration: buildResult must stamp stats.EndTime before copying
// stats into the immutable Result, rather than relying on the outer deferred
// EndTime that runs too late (CR-08).
func TestBuildResultStampsEndTime(t *testing.T) {
	c := &Crawler{fragManager: fragment.NewManager()}
	c.stats.StartTime = time.Now().Add(-2 * time.Second)

	res := c.buildResult(context.Background())

	if res.Stats.EndTime.IsZero() {
		t.Fatal("buildResult left Result.Stats.EndTime at zero — Duration() would underflow")
	}
	if d := res.Duration(); d < 0 {
		t.Fatalf("Result.Duration() = %s, want a non-negative elapsed time", d)
	}
	if d := res.Duration(); d < time.Second {
		t.Fatalf("Result.Duration() = %s, want at least the ~2s elapsed", d)
	}
}

// TestBuildResultStampsEndTimeOnCancelledContext verifies the duration is still
// valid when the crawl was cancelled — buildResult must finalize the end time
// regardless of ctx state (CR-08 + CR-05).
func TestBuildResultStampsEndTimeOnCancelledContext(t *testing.T) {
	c := &Crawler{fragManager: fragment.NewManager()}
	c.stats.StartTime = time.Now().Add(-time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := c.buildResult(ctx)

	if res.Stats.EndTime.IsZero() {
		t.Fatal("EndTime not stamped on a cancelled crawl")
	}
	if d := res.Duration(); d < 0 {
		t.Fatalf("Duration() = %s on cancelled crawl, want non-negative", d)
	}
}

// TestDOMXssProbeBudget covers the cancellation/budget decision the DOM-XSS
// post-pass makes before touching the browser (CR-05): a done context or an
// exhausted deadline must skip the probe, while a live context yields a budget
// capped at both domXssBudget and the parent's remaining time.
func TestDOMXssProbeBudget(t *testing.T) {
	// Already cancelled → skip.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := domXssProbeBudget(cancelled); ok {
		t.Error("cancelled context should skip the probe")
	}

	// Deadline already passed → skip.
	expired, cancel2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel2()
	if _, ok := domXssProbeBudget(expired); ok {
		t.Error("expired deadline should skip the probe")
	}

	// No deadline → full budget.
	if got, ok := domXssProbeBudget(context.Background()); !ok || got != domXssBudget {
		t.Errorf("no-deadline budget = %s ok=%v, want %s true", got, ok, domXssBudget)
	}

	// Short remaining deadline → capped at the remaining time.
	short, cancel3 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel3()
	got, ok := domXssProbeBudget(short)
	if !ok {
		t.Fatal("live short deadline should permit the probe")
	}
	if got > 3*time.Second || got <= 0 {
		t.Errorf("short-deadline budget = %s, want (0, 3s]", got)
	}
	if got >= domXssBudget {
		t.Errorf("short-deadline budget %s should be capped below domXssBudget %s", got, domXssBudget)
	}
}
