package cli

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// TestIsWallTimeout locks in wall-hit detection: a max-duration timeout is a
// graceful stop (finalize + write artifacts), while a transient provider-call
// timeout or a cancel is a real failure. Detection keys off ctx.Err(), not the
// run error, because the engine flattens its error to a string so the sentinel
// is unreachable via errors.Is(runErr, ...).
func TestIsWallTimeout(t *testing.T) {
	// The engine's real error shape: a string-flattened deadline that does NOT
	// unwrap to context.DeadlineExceeded — the reason we can't test runErr.
	flattened := fmt.Errorf("autopilot engine: %s", context.DeadlineExceeded.Error())
	if errors.Is(flattened, context.DeadlineExceeded) {
		t.Fatal("precondition: flattened engine error must NOT unwrap to DeadlineExceeded")
	}

	deadlineCtx, cancelD := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelD()
	canceledCtx, cancelC := context.WithCancel(context.Background())
	cancelC()

	cases := []struct {
		name   string
		ctx    context.Context
		runErr error
		want   bool
	}{
		{"wall fired + engine error -> graceful", deadlineCtx, flattened, true},
		{"wall fired but run succeeded -> not a timeout", deadlineCtx, nil, false},
		{"provider-call timeout, wall un-fired -> failure", context.Background(), flattened, false},
		{"ctrl-c / SIGTERM (canceled) -> failure", canceledCtx, flattened, false},
		{"clean success -> not a timeout", context.Background(), nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWallTimeout(tc.ctx, tc.runErr); got != tc.want {
				t.Fatalf("isWallTimeout = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPrescanBudget locks in the clamp that stops the autopilot native pre-scan
// from consuming the whole session wall (and starving the operator agent) when a
// browser-spider wedges. Regression guard for the pre-scan hang.
func TestPrescanBudget(t *testing.T) {
	cases := []struct {
		name string
		wall time.Duration
		want time.Duration
	}{
		{"typical 15m wall caps at 4m", 15 * time.Minute, 4 * time.Minute},
		{"8m wall -> wall/3", 8 * time.Minute, 8 * time.Minute / 3},
		{"6m wall -> 2m", 6 * time.Minute, 2 * time.Minute},
		{"huge 6h wall still caps at 4m", 6 * time.Hour, 4 * time.Minute},
		{"tiny 45s wall floors at 30s", 45 * time.Second, 30 * time.Second},
		{"sub-floor wall never exceeds the wall itself", 20 * time.Second, 20 * time.Second},
		{"zero wall floors at 30s (defensive)", 0, 30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := prescanBudget(tc.wall)
			if got != tc.want {
				t.Fatalf("prescanBudget(%s) = %s, want %s", tc.wall, got, tc.want)
			}
			// Invariant: the pre-scan may never eat the whole wall when the wall
			// is large enough to leave the agent time.
			if tc.wall >= 90*time.Second && got >= tc.wall {
				t.Fatalf("prescanBudget(%s) = %s did not leave the agent any wall", tc.wall, got)
			}
		})
	}
}
