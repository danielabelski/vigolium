package clicommon

import (
	"testing"
	"time"
)

// fixedNow is the reference "now" for the relative forms: a Tuesday afternoon,
// deliberately in a non-UTC zone so a bound resolved against UTC midnight is
// visibly wrong rather than accidentally right.
func fixedNow(t *testing.T) time.Time {
	t.Helper()
	zone := time.FixedZone("UTC+8", 8*60*60)
	return time.Date(2026, time.August, 5, 14, 30, 0, 0, zone)
}

func TestParseTimeSpecRelative(t *testing.T) {
	now := fixedNow(t)
	tests := []struct {
		in   string
		want time.Duration // offset back from now
	}{
		{"30s", 30 * time.Second},
		{"15m", 15 * time.Minute},
		{"2h", 2 * time.Hour},
		{"2d", 48 * time.Hour},
		{"1w", 7 * 24 * time.Hour},
		{"1h30m", 90 * time.Minute},
		// Word forms resolve via the singular table plus a plural-strip retry,
		// so every unit's plural must round-trip without being listed twice.
		{"3 days", 72 * time.Hour},
		{"2 days ago", 48 * time.Hour},
		{"45 mins", 45 * time.Minute},
		{"30 seconds", 30 * time.Second},
		{"6 hrs", 6 * time.Hour},
		{"2 weeks", 14 * 24 * time.Hour},
		{"1 minute", time.Minute},
		{"-2d", 48 * time.Hour},
		{"2D", 48 * time.Hour},
		// Sub-second Go units must not be read as plurals of a single-letter
		// unit — "ms" as "minutes" would be off by 60000x, silently.
		{"500ms", 500 * time.Millisecond},
		{"200us", 200 * time.Microsecond},
		{"50ns", 50 * time.Nanosecond},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseBoundAt(tt.in, now, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if want := now.Add(-tt.want); !got.Equal(want) {
				t.Errorf("parseBoundAt(%q) = %v, want %v", tt.in, got, want)
			}
		})
	}
}

func TestParseTimeSpecKeywords(t *testing.T) {
	now := fixedNow(t)

	t.Run("today opens at local midnight", func(t *testing.T) {
		got, err := parseBoundAt("today", now, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := time.Date(2026, time.August, 5, 0, 0, 0, 0, now.Location())
		if !got.Equal(want) {
			t.Errorf("since today = %v, want %v", got, want)
		}
	})

	t.Run("today closes at end of day", func(t *testing.T) {
		got, err := parseBoundAt("today", now, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// An upper bound of today must still be after "now", or --until today
		// would exclude everything recorded so far today.
		if !got.After(now) {
			t.Errorf("until today = %v, want an instant after now (%v)", got, now)
		}
		if got.Day() != 5 {
			t.Errorf("until today = %v, want it to stay on the 5th", got)
		}
	})

	t.Run("yesterday", func(t *testing.T) {
		got, err := parseBoundAt("yesterday", now, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := time.Date(2026, time.August, 4, 0, 0, 0, 0, now.Location())
		if !got.Equal(want) {
			t.Errorf("since yesterday = %v, want %v", got, want)
		}
	})

	t.Run("now", func(t *testing.T) {
		got, err := parseBoundAt("now", now, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !got.Equal(now) {
			t.Errorf("since now = %v, want %v", got, now)
		}
	})
}

// TestParseTimeSpecUsesLocalMidnight pins the timezone contract: a bare date is
// the user's own midnight. Resolving it in UTC dropped the first hours of the
// local day for anyone east of Greenwich.
func TestParseTimeSpecUsesLocalMidnight(t *testing.T) {
	now := fixedNow(t)
	got, err := parseBoundAt("2026-08-05", now, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2026, time.August, 5, 0, 0, 0, 0, now.Location())
	if !got.Equal(want) {
		t.Fatalf("since 2026-08-05 = %v, want local midnight %v", got, want)
	}
	if _, offset := got.Zone(); offset != 8*60*60 {
		t.Errorf("resolved in zone offset %d, want the caller's +8", offset)
	}
}

// TestParseTimeSpecBareDateUpperBoundCoversWholeDay pins the other half of the
// range contract: "--to <date>" must include the day it names.
func TestParseTimeSpecBareDateUpperBoundCoversWholeDay(t *testing.T) {
	now := fixedNow(t)
	got, err := parseBoundAt("2026-08-05", now, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lateThatDay := time.Date(2026, time.August, 5, 23, 59, 59, 0, now.Location())
	if !got.After(lateThatDay) {
		t.Errorf("until 2026-08-05 = %v, want it to cover through %v", got, lateThatDay)
	}
	nextDay := time.Date(2026, time.August, 6, 0, 0, 0, 0, now.Location())
	if !got.Before(nextDay) {
		t.Errorf("until 2026-08-05 = %v, want it to stop before %v", got, nextDay)
	}
}

func TestParseTimeSpecAbsolute(t *testing.T) {
	now := fixedNow(t)
	loc := now.Location()
	tests := []struct {
		in   string
		want time.Time
	}{
		{"2026-08-05 14:30", time.Date(2026, time.August, 5, 14, 30, 0, 0, loc)},
		{"2026-08-05T14:30", time.Date(2026, time.August, 5, 14, 30, 0, 0, loc)},
		{"2026-08-05 14:30:45", time.Date(2026, time.August, 5, 14, 30, 45, 0, loc)},
		{"2026-08-05T14:30:45", time.Date(2026, time.August, 5, 14, 30, 45, 0, loc)},
		// RFC3339 carries its own offset and is honored as written.
		{"2026-08-05T14:30:45Z", time.Date(2026, time.August, 5, 14, 30, 45, 0, time.UTC)},
		{"2026-08-05T14:30:45+08:00", time.Date(2026, time.August, 5, 14, 30, 45, 0, loc)},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseBoundAt(tt.in, now, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("parseBoundAt(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestParseTimeSpecPreciseValuesDoNotSnap guards the dayOnly rule: only a value
// that named a whole day may be widened to end-of-day.
func TestParseTimeSpecPreciseValuesDoNotSnap(t *testing.T) {
	now := fixedNow(t)
	for _, in := range []string{"2026-08-05 14:30", "2026-08-05T14:30:45Z", "2h", "now"} {
		t.Run(in, func(t *testing.T) {
			lower, err := parseBoundAt(in, now, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			upper, err := parseBoundAt(in, now, true)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !lower.Equal(upper) {
				t.Errorf("%q resolved differently as bound (%v) vs upper bound (%v)", in, lower, upper)
			}
		})
	}
}

func TestParseTimeSpecRejects(t *testing.T) {
	now := fixedNow(t)
	for _, in := range []string{"", "   ", "not-a-date", "7", "5x", "tomorrow", "2026-13-45", "last tuesday"} {
		t.Run(in, func(t *testing.T) {
			if got, err := parseBoundAt(in, now, false); err == nil {
				t.Errorf("parseBoundAt(%q) = %v, want an error", in, got)
			}
		})
	}
}

// TestParseRelativeOffsetOverflow guards the n*unit multiplication: a huge count
// must be rejected, not silently wrapped into a negative duration (which would
// turn "since" into a bound in the future and match nothing).
func TestParseRelativeOffsetOverflow(t *testing.T) {
	for _, in := range []string{"9223372036854775807w", "99999999999999999999d"} {
		if d, ok := parseRelativeOffset(in); ok && d < 0 {
			t.Errorf("parseRelativeOffset(%q) = %v, want rejection rather than a negative duration", in, d)
		}
	}
}

func TestFormatTimeFilter(t *testing.T) {
	loc := time.Local
	day := time.Date(2026, time.August, 5, 0, 0, 0, 0, loc)

	if got, want := FormatTimeFilter(day), "2026-08-05"; got != want {
		t.Errorf("midnight formatted as %q, want %q", got, want)
	}
	if got, want := FormatTimeFilter(endOfDay(day)), "2026-08-05"; got != want {
		t.Errorf("end-of-day formatted as %q, want %q", got, want)
	}
	mid := time.Date(2026, time.August, 5, 14, 30, 0, 0, loc)
	if got, want := FormatTimeFilter(mid), "2026-08-05 14:30"; got != want {
		t.Errorf("mid-day formatted as %q, want %q", got, want)
	}
}
