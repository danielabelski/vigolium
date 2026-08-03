package cli

import (
	"testing"
	"time"
)

// resetTrafficReplayFlags clears the traffic-side globals the shim reads, so a
// test starts from a known state (they persist across cobra runs in-process).
func resetTrafficReplayFlags(t *testing.T) {
	t.Helper()
	reset := func() {
		trafficHost = ""
		trafficMethods = nil
		trafficStatus = nil
		trafficPath = ""
		trafficSource = ""
		trafficSearch = nil
		trafficHeader = ""
		trafficBody = ""
		trafficExcludeSearch = nil
		trafficExcludeHeader = ""
		trafficExcludeBody = ""
		trafficFrom = ""
		trafficTo = ""
		trafficSort = "created_at"
		trafficAsc = false
		trafficOffset = 0
		trafficLimit = 100
		trafficAll = false
		trafficReplayConcurrency = 10
		trafficReplayBrowser = false
		trafficBurpBridgeURL = ""
		globalTimeout = 15 * time.Second
	}
	reset()
	t.Cleanup(reset)
}

// The shim hands traffic's own filters to replay rather than re-deriving them,
// so `--replay` selects exactly what the listing would have shown. This is the
// property that used to require a 20-field mapping test.
func TestTrafficReplayShim_UsesTrafficSelection(t *testing.T) {
	resetTrafficReplayFlags(t)
	resetReplayBulkFlags(t)
	trafficHost = "*.example.com"
	trafficMethods = []string{"GET", "POST"}
	trafficHeader = "X-Api-Key"
	trafficExcludeHeader = "X-Internal"
	trafficLimit = 50
	globalStateless = true // project scoping off → no DB lookup

	f, err := buildTrafficFilters("dashboard")
	if err != nil {
		t.Fatalf("buildTrafficFilters: %v", err)
	}

	if f.HostPattern != "*.example.com" || len(f.Methods) != 2 {
		t.Errorf("Host=%q Methods=%v", f.HostPattern, f.Methods)
	}
	// traffic --header is a search filter, and reaches replay as one — the
	// -H/--header override must stay empty.
	if f.HeaderSearch != "X-Api-Key" || f.ExcludeHeaderSearch != "X-Internal" {
		t.Errorf("HeaderSearch=%q ExcludeHeaderSearch=%q", f.HeaderSearch, f.ExcludeHeaderSearch)
	}
	if len(replayHeaders) != 0 {
		t.Errorf("--header overlay = %v, want empty (traffic --header is a filter)", replayHeaders)
	}
	if f.FuzzyTerm != "dashboard" {
		t.Errorf("FuzzyTerm = %q, want dashboard", f.FuzzyTerm)
	}
	// The -n/--limit cap survives: an unfiltered --replay re-sends the page the
	// command would have listed, not the whole database.
	if f.Limit != 50 {
		t.Errorf("Limit = %d, want 50", f.Limit)
	}
}

// An unfiltered `traffic --replay` must not silently widen to every stored
// record — it replays the same capped page `traffic` would have listed.
func TestTrafficReplayShim_UnfilteredKeepsLimit(t *testing.T) {
	resetTrafficReplayFlags(t)
	resetReplayBulkFlags(t)
	globalStateless = true

	f, err := buildTrafficFilters("")
	if err != nil {
		t.Fatalf("buildTrafficFilters: %v", err)
	}
	if f.Limit != 100 {
		t.Errorf("Limit = %d, want the default 100 cap", f.Limit)
	}

	trafficAll = true
	f, err = buildTrafficFilters("")
	if err != nil {
		t.Fatalf("buildTrafficFilters: %v", err)
	}
	if f.Limit != 0 {
		t.Errorf("Limit = %d, want 0 (--all lifts the cap)", f.Limit)
	}
}

// traffic --replay never followed redirects; following them would change the
// status the comparison reports, so the shortcut must preserve it.
func TestTrafficReplayShim_PreservesNoRedirects(t *testing.T) {
	resetTrafficReplayFlags(t)
	resetReplayBulkFlags(t)
	applyTrafficReplayFlags()
	if !replayNoRedirects {
		t.Error("replayNoRedirects = false, want true (traffic --replay does not follow redirects)")
	}
}

// traffic's default output is the comparison table; replay's is JSON. The
// shortcut keeps traffic's default unless -j asked for the machine shape.
func TestTrafficReplayShim_OutputShape(t *testing.T) {
	t.Run("default is pretty", func(t *testing.T) {
		resetTrafficReplayFlags(t)
		resetReplayBulkFlags(t)
		globalJSON = false
		applyTrafficReplayFlags()
		if !replayPretty {
			t.Error("replayPretty = false, want true when -j is not set")
		}
	})
	t.Run("-j yields JSONL", func(t *testing.T) {
		resetTrafficReplayFlags(t)
		resetReplayBulkFlags(t)
		globalJSON = true
		applyTrafficReplayFlags()
		if replayPretty {
			t.Error("replayPretty = true, want false under -j")
		}
	})
}

func TestTrafficReplayShim_MapsSendBehaviour(t *testing.T) {
	resetTrafficReplayFlags(t)
	resetReplayBulkFlags(t)
	trafficReplayConcurrency = 3
	trafficReplayBrowser = true
	trafficBurpBridgeURL = "http://127.0.0.1:9009"
	globalTimeout = 42 * time.Second

	applyTrafficReplayFlags()

	if replayConcurrency != 3 {
		t.Errorf("replayConcurrency = %d, want 3", replayConcurrency)
	}
	if !replayWithBrowser {
		t.Error("replayWithBrowser = false, want true")
	}
	if replayBurpBridgeURL != "http://127.0.0.1:9009" {
		t.Errorf("replayBurpBridgeURL = %q", replayBurpBridgeURL)
	}
	if replayTimeout != 42*time.Second {
		t.Errorf("replayTimeout = %v, want 42s", replayTimeout)
	}
}
