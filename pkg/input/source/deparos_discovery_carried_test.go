package source

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestBuildDiscoveryHeaders_InjectsSessionForMatchingHost(t *testing.T) {
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{
		BrowserSessions: map[string]httpmsg.CarriedSession{
			"example.com": {CookieHeader: "cf_clearance=abc", UserAgent: "PinnedUA/1.0"},
		},
	}}

	headers := d.buildDiscoveryHeaders("https://example.com/app")
	if headers["Cookie"] != "cf_clearance=abc" {
		t.Errorf("Cookie = %q, want carried cookie", headers["Cookie"])
	}
	if headers["User-Agent"] != "PinnedUA/1.0" {
		t.Errorf("User-Agent = %q, want carried UA", headers["User-Agent"])
	}
}

func TestBuildDiscoveryHeaders_NonMatchingHostGetsNothing(t *testing.T) {
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{
		BrowserSessions: map[string]httpmsg.CarriedSession{
			"example.com": {CookieHeader: "cf_clearance=abc"},
		},
	}}

	// A different host must not inherit example.com's session.
	if headers := d.buildDiscoveryHeaders("https://other.test/"); headers != nil {
		t.Errorf("expected nil headers for non-matching host, got %v", headers)
	}
}

func TestBuildDiscoveryHeaders_ConfiguredHeaderWins(t *testing.T) {
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{
		CustomHeaders: map[string]string{"cookie": "operator=1"}, // lowercase on purpose
		BrowserSessions: map[string]httpmsg.CarriedSession{
			"example.com": {CookieHeader: "cf_clearance=abc", UserAgent: "PinnedUA/1.0"},
		},
	}}

	headers := d.buildDiscoveryHeaders("https://example.com/")
	// A configured Cookie (any case) wins; the session's Cookie is not added.
	if headers["cookie"] != "operator=1" {
		t.Errorf("configured cookie = %q, want operator=1", headers["cookie"])
	}
	if _, ok := headers["Cookie"]; ok {
		t.Error("session Cookie must not be added when a Cookie header is already configured")
	}
	// User-Agent was not configured, so the session's UA is still injected.
	if headers["User-Agent"] != "PinnedUA/1.0" {
		t.Errorf("User-Agent = %q, want carried UA", headers["User-Agent"])
	}
}

func TestBuildDiscoveryHeaders_NoSessionNoCustomIsNil(t *testing.T) {
	d := &DeparosDiscoverySource{cfg: DeparosDiscoveryConfig{}}
	if headers := d.buildDiscoveryHeaders("https://example.com/"); headers != nil {
		t.Errorf("expected nil headers with no session and no custom headers, got %v", headers)
	}
}
