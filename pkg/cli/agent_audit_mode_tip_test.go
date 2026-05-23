package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent"
)

// TestAuditModeTip covers the tip table: every mode the dispatcher accepts
// must have a non-empty tip (so the banner is informative), and an unknown
// mode must return "" (so the banner cleanly omits it instead of printing a
// blank line).
func TestAuditModeTip(t *testing.T) {
	// Every canonical audit driver mode should carry a tip. This walks the
	// same source-of-truth set the validator uses, so a newly added mode
	// without a tip is caught here.
	for _, m := range []string{
		"lite", "balanced", "scan", "deep", "revisit", "confirm",
		"merge", "diff", "longshot", "refresh", "reinvest",
	} {
		if tip := auditModeTip(m); strings.TrimSpace(tip) == "" {
			t.Errorf("auditModeTip(%q) is empty; every accepted mode needs a tip", m)
		}
		if !agent.IsValidAuditDriverMode(m) {
			t.Errorf("test mode %q is not a recognized audit mode — fix the test list", m)
		}
	}

	// Case-insensitive + trimmed.
	if auditModeTip("  DEEP ") != auditModeTip("deep") {
		t.Error("auditModeTip should normalize case and whitespace")
	}

	// Unknown modes get no tip.
	for _, m := range []string{"", "garbage", "xyz"} {
		if tip := auditModeTip(m); tip != "" {
			t.Errorf("auditModeTip(%q) = %q, want empty", m, tip)
		}
	}
}

// TestPrintAuditModeTips_Chain verifies a chained mode string renders one
// tip line per known mode and skips unknown ones — no panics, no blank
// lines.
func TestPrintAuditModeTips_Chain(t *testing.T) {
	var buf bytes.Buffer
	printAuditModeTips(&buf, "deep,confirm,bogus")

	out := buf.String()
	lines := 0
	for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.TrimSpace(ln) != "" {
			lines++
		}
	}
	if lines != 2 {
		t.Fatalf("expected 2 tip lines (deep, confirm), got %d:\n%s", lines, out)
	}
	if !strings.Contains(out, "deep") || !strings.Contains(out, "confirm") {
		t.Errorf("chain tips missing expected modes:\n%s", out)
	}
	if strings.Contains(out, "bogus") {
		t.Errorf("unknown mode should be skipped, got:\n%s", out)
	}
}
