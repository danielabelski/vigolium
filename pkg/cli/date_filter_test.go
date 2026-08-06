package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestParseDateRangeFlags(t *testing.T) {
	t.Run("both empty", func(t *testing.T) {
		from, to, err := parseDateRangeFlags("", "", "--from", "--to")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if from != nil || to != nil {
			t.Errorf("from=%v to=%v, want both nil (unbounded)", from, to)
		}
	})

	t.Run("relative lower bound", func(t *testing.T) {
		before := time.Now().Add(-2 * time.Hour)
		from, to, err := parseDateRangeFlags("2h", "", "--from", "--to")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if to != nil {
			t.Errorf("to = %v, want nil", to)
		}
		if from == nil || from.Before(before.Add(-time.Minute)) || from.After(time.Now()) {
			t.Errorf("from = %v, want roughly 2h ago", from)
		}
	})

	// The error must name the flag the user actually typed, not a canonical one.
	t.Run("invalid value names the flag", func(t *testing.T) {
		_, _, err := parseDateRangeFlags("nonsense", "", "--since", "--until")
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "--since") {
			t.Errorf("error %q does not name --since", err)
		}
	})

	// An inverted range silently matches nothing, which reads as "no results"
	// rather than "you typed the bounds backwards".
	t.Run("inverted range is rejected", func(t *testing.T) {
		_, _, err := parseDateRangeFlags("2026-08-05", "2026-08-01", "--from", "--to")
		if err == nil {
			t.Fatal("expected an error for an inverted range")
		}
		if !strings.Contains(err.Error(), "matches nothing") {
			t.Errorf("error %q does not explain the empty range", err)
		}
	})

	// A single day as both bounds is a valid (and common) one-day window: the
	// upper bound's end-of-day snap is what keeps it non-empty.
	t.Run("same day on both bounds is a full day", func(t *testing.T) {
		from, to, err := parseDateRangeFlags("2026-08-05", "2026-08-05", "--from", "--to")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if from == nil || to == nil {
			t.Fatalf("from=%v to=%v, want both set", from, to)
		}
		if span := to.Sub(*from); span < 23*time.Hour {
			t.Errorf("single-day window spans %v, want ~24h", span)
		}
	})

}

// The label is derived from the alias table rather than hand-written, so it must
// name every accepted spelling — that is what keeps error text from going stale
// when an alias is added.
func TestFlagAliasLabel(t *testing.T) {
	if got, want := flagAliasLabel(timeFilterAliases, "from"), "--from/--since"; got != want {
		t.Errorf("from label = %q, want %q", got, want)
	}
	if got, want := flagAliasLabel(timeFilterAliases, "to"), "--to/--until"; got != want {
		t.Errorf("to label = %q, want %q", got, want)
	}
	// Deterministic ordering: map iteration is random, so a multi-alias label
	// must sort rather than flake.
	multi := map[string]string{"b": "x", "a": "x", "c": "y"}
	if got, want := flagAliasLabel(multi, "x"), "--x/--a/--b"; got != want {
		t.Errorf("multi-alias label = %q, want %q", got, want)
	}
	if got, want := flagAliasLabel(multi, "unaliased"), "--unaliased"; got != want {
		t.Errorf("unaliased label = %q, want %q", got, want)
	}
}

// addFlagAliases accumulates instead of overwriting: cobra's
// SetGlobalNormalizationFunc is a plain setter, so two independent registrations
// racing for that slot would leave whichever ran first silently dead. Order must
// not matter.
func TestAddFlagAliasesComposesInEitherOrder(t *testing.T) {
	for _, order := range [][]map[string]string{
		{{"sev": "severity"}, timeFilterAliases},
		{timeFilterAliases, {"sev": "severity"}},
	} {
		cmd := &cobra.Command{Use: "probe"}
		cmd.Flags().String("severity", "", "")
		cmd.Flags().String("from", "", "")
		cmd.Flags().String("to", "", "")
		for _, set := range order {
			addFlagAliases(cmd, set)
		}
		t.Cleanup(func() { delete(flagAliases, cmd) })

		if err := cmd.ParseFlags([]string{"--sev", "high", "--since", "2d", "--until", "today"}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		for flag, want := range map[string]string{"severity": "high", "from": "2d", "to": "today"} {
			if got, _ := cmd.Flags().GetString(flag); got != want {
				t.Errorf("--%s = %q, want %q (registration order must not matter)", flag, got, want)
			}
		}
	}
}

// TestTimeFilterAliasesResolve verifies --since/--until reach the same flags as
// --from/--to on every command that filters by time, rather than being silently
// ignored. `traffic --replay` and `replay` share one selection path, so an alias
// on one and not the other would be a visible inconsistency.
func TestTimeFilterAliasesResolve(t *testing.T) {
	for _, tc := range []struct {
		path           []string
		since, until   string
		fromVar, toVar *string
	}{
		{[]string{"finding"}, "2d", "today", &findingFrom, &findingTo},
		{[]string{"traffic"}, "3h", "2026-08-05", &trafficFrom, &trafficTo},
		{[]string{"replay"}, "4d", "yesterday", &replayBulkFrom, &replayBulkTo},
		{[]string{"db", "ls"}, "5h", "today", &listFrom, &listTo},
		{[]string{"db", "export"}, "6h", "today", &exportFrom, &exportTo},
	} {
		t.Run(strings.Join(tc.path, " "), func(t *testing.T) {
			*tc.fromVar, *tc.toVar = "", ""
			t.Cleanup(func() { *tc.fromVar, *tc.toVar = "", "" })

			cmd, _, err := rootCmd.Find(tc.path)
			if err != nil {
				t.Fatalf("find %v: %v", tc.path, err)
			}
			if err := cmd.ParseFlags([]string{"--since", tc.since, "--until", tc.until}); err != nil {
				t.Fatalf("ParseFlags: %v", err)
			}
			if *tc.fromVar != tc.since {
				t.Errorf("--since did not reach --from: got %q, want %q", *tc.fromVar, tc.since)
			}
			if *tc.toVar != tc.until {
				t.Errorf("--until did not reach --to: got %q, want %q", *tc.toVar, tc.until)
			}
		})
	}
}

// finding registers two alias sets (--sev and the time filters); folding them
// into one table must not have dropped the pre-existing one.
func TestFindingSevAliasStillResolves(t *testing.T) {
	findingSeverity = ""
	t.Cleanup(func() { findingSeverity = "" })

	cmd, _, err := rootCmd.Find([]string{"finding"})
	if err != nil {
		t.Fatalf("find finding: %v", err)
	}
	if err := cmd.ParseFlags([]string{"--sev", "high"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if findingSeverity != "high" {
		t.Errorf("--sev did not reach --severity: got %q", findingSeverity)
	}
}

// The bounds must reach the query filters both commands build, not just parse.
func TestListingCommandsApplyTimeBounds(t *testing.T) {
	globalStateless = true // project scoping off → no DB lookup
	t.Cleanup(func() { globalStateless = false })

	t.Run("traffic", func(t *testing.T) {
		resetTrafficReplayFlags(t)
		trafficFrom, trafficTo = "yesterday", "today"
		f, err := buildTrafficFilters("")
		if err != nil {
			t.Fatalf("buildTrafficFilters: %v", err)
		}
		if f.DateFrom == nil || f.DateTo == nil {
			t.Fatalf("DateFrom=%v DateTo=%v, want both set", f.DateFrom, f.DateTo)
		}
		if !f.DateTo.After(*f.DateFrom) {
			t.Errorf("DateTo (%v) is not after DateFrom (%v)", f.DateTo, f.DateFrom)
		}
	})

	t.Run("finding", func(t *testing.T) {
		findingFrom, findingTo = "7d", ""
		findingRecordKind = ""
		t.Cleanup(func() { findingFrom, findingTo = "", "" })

		f, err := buildFindingFilters("")
		if err != nil {
			t.Fatalf("buildFindingFilters: %v", err)
		}
		if f.DateFrom == nil {
			t.Fatal("DateFrom is nil, want ~7 days ago")
		}
		if age := time.Since(*f.DateFrom); age < 6*24*time.Hour || age > 8*24*time.Hour {
			t.Errorf("DateFrom is %v old, want ~7 days", age)
		}
	})
}
