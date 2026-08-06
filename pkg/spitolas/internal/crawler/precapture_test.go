package crawler

import (
	"strings"
	"testing"
)

// The gate exists so the settle — which has a floor of one poll window and a
// ceiling of many seconds — is not paid on every executed action. An empty
// previousURL must therefore fall through to the busy probe rather than
// short-circuiting to "navigated", which is what made a once-per-crawl-loop
// caller settle unconditionally.
func TestSettleGateIgnoresEmptyPreviousURL(t *testing.T) {
	tests := []struct {
		name        string
		previousURL string
		state       pageState
		wantSettle  bool
	}{
		{
			name:        "no previous URL and quiet page does not settle",
			previousURL: "",
			state:       pageState{URL: "https://app.test/x", Busy: false},
			wantSettle:  false,
		},
		{
			name:        "no previous URL but busy page settles",
			previousURL: "",
			state:       pageState{URL: "https://app.test/x", Busy: true},
			wantSettle:  true,
		},
		{
			name:        "same URL and quiet page does not settle",
			previousURL: "https://app.test/x",
			state:       pageState{URL: "https://app.test/x", Busy: false},
			wantSettle:  false,
		},
		{
			name:        "moved URL settles even when quiet",
			previousURL: "https://app.test/x",
			state:       pageState{URL: "https://app.test/y", Busy: false},
			wantSettle:  true,
		},
		{
			name:        "hash route change counts as a move",
			previousURL: "https://app.test/#/a",
			state:       pageState{URL: "https://app.test/#/b", Busy: false},
			wantSettle:  true,
		},
		{
			name:        "unreadable URL falls back to the busy probe",
			previousURL: "https://app.test/x",
			state:       pageState{URL: "", Busy: false},
			wantSettle:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mirrors the decision in settleBeforeCapture. Kept as a direct
			// expression so the gate can be asserted without a live browser.
			navigated := tt.previousURL != "" && tt.state.URL != "" &&
				!sameDocumentURL(tt.state.URL, tt.previousURL)
			got := navigated || tt.state.Busy
			if got != tt.wantSettle {
				t.Errorf("settle gate = %v, want %v (navigated=%v busy=%v)",
					got, tt.wantSettle, navigated, tt.state.Busy)
			}
		})
	}
}

// The probe answers both questions in one round-trip because it runs on every
// action; splitting it would double the CDP traffic on the hottest path.
func TestPageStateScriptReturnsBothFields(t *testing.T) {
	for _, want := range []string{"location.href", "readyState", "aria-busy", "JSON.stringify(out)"} {
		if !strings.Contains(pageStateScript, want) {
			t.Errorf("page-state probe no longer references %q", want)
		}
	}
	// A permanently-present but hidden spinner must not read as busy, or every
	// state pays the deep settle.
	if !strings.Contains(pageStateScript, "checkVisibility") ||
		!strings.Contains(pageStateScript, "getBoundingClientRect") {
		t.Error("visibility test missing; hidden spinner markup would report busy")
	}
}
