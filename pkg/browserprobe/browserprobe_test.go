package browserprobe

import (
	"strings"
	"testing"
)

func TestLaunchableEmptyPath(t *testing.T) {
	if err := Launchable(""); err == nil {
		t.Fatal("Launchable(\"\") should error on empty path")
	}
	if err := Launchable("   "); err == nil {
		t.Fatal("Launchable(whitespace) should error on empty path")
	}
}

// TestLaunchableMissingBinary verifies a non-existent binary is reported as a
// launch failure rather than hanging or panicking. Real-browser success is
// covered by the integration-tagged spider tests, not here.
func TestLaunchableMissingBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a launcher subprocess; skipped under -short")
	}
	err := Launchable("/nonexistent/definitely-not-a-browser-xyz")
	if err == nil {
		t.Fatal("Launchable() on a missing binary should return an error")
	}
	if !strings.Contains(err.Error(), "did not start") {
		t.Errorf("expected a 'did not start' error, got: %v", err)
	}
}

func TestFirstLine(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"single", "boom", "boom"},
		{"trims", "  boom  ", "boom"},
		{"multiline", "[launcher] Failed to get the debug url: ...\n[ERROR:cpufreq]", "[launcher] Failed to get the debug url: ..."},
		{"leading blank lines", "\n\n  real error\nmore", "real error"},
		{"empty", "", ""},
		{"only newlines", "\n\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FirstLine(tt.in); got != tt.want {
				t.Errorf("FirstLine(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
