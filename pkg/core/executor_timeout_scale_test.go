package core

import (
	"testing"
	"time"
)

// TestScaleModuleTimeout verifies that the per-module timeout scales with a
// whole-request module's insertion-point count, is a no-op at or below the
// reference count, and never exceeds maxModuleTimeoutScale x the base.
func TestScaleModuleTimeout(t *testing.T) {
	base := 300 * time.Second
	cases := []struct {
		name      string
		base      time.Duration
		workUnits int
		want      time.Duration
	}{
		{"below reference is unscaled", base, timeoutScaleRefPoints - 1, base},
		{"at reference is unscaled", base, timeoutScaleRefPoints, base},
		{"2x insertion points doubles", base, timeoutScaleRefPoints * 2, 2 * base},
		{"3x insertion points triples", base, timeoutScaleRefPoints * 3, 3 * base},
		{"capped at max scale", base, timeoutScaleRefPoints * 100, maxModuleTimeoutScale * base},
		{"exactly at cap boundary", base, timeoutScaleRefPoints * maxModuleTimeoutScale, maxModuleTimeoutScale * base},
		{"zero work units unscaled", base, 0, base},
		{"non-positive base is unchanged", 0, timeoutScaleRefPoints * 4, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scaleModuleTimeout(tc.base, tc.workUnits); got != tc.want {
				t.Fatalf("scaleModuleTimeout(%s, %d) = %s, want %s", tc.base, tc.workUnits, got, tc.want)
			}
		})
	}
}

// TestScaleModuleTimeout_NeverBelowBase asserts scaling only ever raises (or keeps)
// the timeout — a scaled call must never shorten a module's budget.
func TestScaleModuleTimeout_NeverBelowBase(t *testing.T) {
	base := 120 * time.Second
	for w := 1; w <= timeoutScaleRefPoints*20; w++ {
		if got := scaleModuleTimeout(base, w); got < base {
			t.Fatalf("scaleModuleTimeout(%s, %d) = %s shortened the base timeout", base, w, got)
		}
	}
}
