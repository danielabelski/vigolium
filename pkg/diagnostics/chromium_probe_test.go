package diagnostics

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// withProbe swaps browserLaunchProbe for the duration of a test.
func withProbe(t *testing.T, probe func(string) error) {
	t.Helper()
	orig := browserLaunchProbe
	browserLaunchProbe = probe
	t.Cleanup(func() { browserLaunchProbe = orig })
}

func TestProbeChromiumHealthy(t *testing.T) {
	called := ""
	withProbe(t, func(p string) error { called = p; return nil })

	in := &ToolCheck{Status: StatusOK, Path: "/usr/bin/chromium", Details: []string{"resolved"}}
	got := probeChromium(in)

	if got.Status != StatusOK {
		t.Fatalf("healthy browser should stay OK, got %v", got.Status)
	}
	if called != "/usr/bin/chromium" {
		t.Errorf("probe should run on the resolved path, called=%q", called)
	}
	if !slices.Contains(got.Details, "launch probe: ok") {
		t.Errorf("expected an 'ok' probe detail, got %v", got.Details)
	}
}

func TestProbeChromiumBrokenDowngrades(t *testing.T) {
	withProbe(t, func(string) error { return fmt.Errorf("browser did not start: SIGTRAP") })

	in := &ToolCheck{Status: StatusOK, Path: "/usr/bin/chromium", Details: []string{"resolved"}}
	got := probeChromium(in)

	if got.Status != StatusWarning {
		t.Fatalf("a crash-on-launch browser must downgrade to Warning, got %v", got.Status)
	}
	if !strings.Contains(got.Message, "failed to launch") {
		t.Errorf("message should explain the launch failure, got %q", got.Message)
	}
	if !strings.Contains(strings.ToLower(got.Tip), "chrome for testing") {
		t.Errorf("tip should point at the Chrome-for-Testing remedy, got %q", got.Tip)
	}
	// The failing-probe row must count as fixable so `doctor --fix` re-installs.
	r := &Report{Tools: map[string]*ToolCheck{"chromium": got}}
	if !toolFailing(r, "chromium") {
		t.Error("downgraded chromium row should be treated as failing/fixable")
	}
}

// A row that never resolved (or has no path) must pass through untouched and
// must NOT trigger a probe — there's nothing to launch.
func TestProbeChromiumPassthrough(t *testing.T) {
	probed := false
	withProbe(t, func(string) error { probed = true; return nil })

	for _, in := range []*ToolCheck{
		nil,
		{Status: StatusWarning, Message: "not found in PATH"},
		{Status: StatusOK, Path: ""},
	} {
		got := probeChromium(in)
		if got != in {
			t.Errorf("passthrough case mutated the row: in=%v out=%v", in, got)
		}
	}
	if probed {
		t.Error("probe should not run for unresolved / pathless rows")
	}
}
