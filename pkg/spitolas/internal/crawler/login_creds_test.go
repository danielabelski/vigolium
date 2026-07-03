package crawler

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/form"
)

func newLoginTestCrawler(t *testing.T, target string) *Crawler {
	t.Helper()
	cfg, err := config.New(target)
	if err != nil {
		t.Fatalf("config.New(%q): %v", target, err)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestHostOf(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://Acme.com/login", "acme.com"},
		{"http://idp.example.org:443/x", "idp.example.org"},
		{"/relative/path", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := hostOf(tt.in); got != tt.want {
			t.Errorf("hostOf(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestClaimLoginCredHost(t *testing.T) {
	c := newLoginTestCrawler(t, "https://acme.com")
	if !c.claimLoginCredHost("acme.com") {
		t.Fatal("first claim should succeed")
	}
	if c.claimLoginCredHost("acme.com") {
		t.Error("second claim for same host should fail (single-flight)")
	}
	if !c.claimLoginCredHost("other.com") {
		t.Error("claim for a new host should succeed")
	}
}

func TestLoginActionInScope(t *testing.T) {
	c := newLoginTestCrawler(t, "https://acme.com")
	loginURL := "https://acme.com/login"

	tests := []struct {
		name   string
		action string
		want   bool
	}{
		{"same host absolute", "https://acme.com/session", true},
		{"empty action (relative)", "", true},
		{"configured target host", "https://acme.com/api/login", true},
		{"external IdP", "https://login.microsoftonline.com/authorize", false},
		{"other third party", "https://evil.example/collect", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.loginActionInScope(tt.action, loginURL); got != tt.want {
				t.Errorf("loginActionInScope(%q) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}

	// An adopted host is also in scope.
	c.adoptedHost = "relocated.com"
	if !c.loginActionInScope("https://relocated.com/login", loginURL) {
		t.Error("adopted host action should be in scope")
	}
}

func TestDedupeCreds(t *testing.T) {
	in := [][2]string{
		{"admin", "admin"},
		{"admin", "admin"}, // dup
		{"root", "root"},
		{"admin", "123456"},
	}
	out := dedupeCreds(in)
	if len(out) != 3 {
		t.Fatalf("dedupeCreds len = %d, want 3", len(out))
	}
	if out[0] != [2]string{"admin", "admin"} || out[1] != [2]string{"root", "root"} {
		t.Errorf("dedupeCreds order not preserved: %v", out)
	}
}

func TestBuildLoginCredsUsernameFormFull(t *testing.T) {
	c := newLoginTestCrawler(t, "https://acme.com")
	creds := c.buildLoginCreds(false, true) // username field, full list (deep)
	if len(creds) != len(commonLoginUserCreds) {
		t.Fatalf("full username creds len = %d, want %d", len(creds), len(commonLoginUserCreds))
	}
	if creds[0] != [2]string{"admin", "admin"} {
		t.Errorf("first cred = %v, want admin:admin", creds[0])
	}
	// email-only pairs must not appear for a username form.
	for _, p := range creds {
		if p == [2]string{"admin@admin.com", "admin"} {
			t.Error("email creds leaked into username form list")
		}
	}
}

// TestBuildLoginCredsUsernameFormMinimal verifies the balanced (minimal) list is
// exactly admin:admin + admin:123456.
func TestBuildLoginCredsUsernameFormMinimal(t *testing.T) {
	c := newLoginTestCrawler(t, "https://acme.com")
	creds := c.buildLoginCreds(false, false) // username field, minimal list (balanced)
	want := [][2]string{{"admin", "admin"}, {"admin", "123456"}}
	if len(creds) != len(want) {
		t.Fatalf("minimal creds = %v, want %v", creds, want)
	}
	for i := range want {
		if creds[i] != want[i] {
			t.Errorf("minimal cred[%d] = %v, want %v", i, creds[i], want[i])
		}
	}
}

func TestBuildLoginCredsEmailFormAddsTargetDerived(t *testing.T) {
	c := newLoginTestCrawler(t, "https://acme.com")
	creds := c.buildLoginCreds(true, true) // email field, full list
	if len(creds) == 0 {
		t.Fatal("expected common email creds")
	}
	// Target-derived admin@<domain> is tried first.
	if creds[0] != [2]string{"admin@acme.com", "admin"} {
		t.Errorf("first email cred = %v, want admin@acme.com:admin", creds[0])
	}
}

// TestBuildLoginCredsEmailFormMinimal verifies the balanced email set stays tiny
// (target-derived admin@domain with two passwords + one generic fallback).
func TestBuildLoginCredsEmailFormMinimal(t *testing.T) {
	c := newLoginTestCrawler(t, "https://acme.com")
	creds := c.buildLoginCreds(true, false)
	if len(creds) != 3 {
		t.Fatalf("minimal email creds = %v, want 3", creds)
	}
	if creds[0] != [2]string{"admin@acme.com", "admin"} {
		t.Errorf("first minimal email cred = %v, want admin@acme.com:admin", creds[0])
	}
	// No full-list-only pair should appear.
	for _, p := range creds {
		if p == [2]string{"admin@example.com", "admin"} || p == [2]string{"test@test.com", "test"} {
			t.Errorf("full-list email cred %v leaked into minimal set", p)
		}
	}
}

func TestBuildLoginCredsReusesRegisteredIdentity(t *testing.T) {
	c := newLoginTestCrawler(t, "https://acme.com")
	fc := c.formHandler.FillContext()
	if fc == nil {
		t.Fatal("expected a FillContext on the handler")
	}
	// Simulate a signup earlier in the crawl.
	fc.Remember(form.SemUsername, "crawluser")
	fc.Remember(form.SemPassword, "Server2018!!")

	// The registered identity is tried first regardless of list size.
	for _, full := range []bool{true, false} {
		creds := c.buildLoginCreds(false, full)
		if creds[0] != [2]string{"crawluser", "Server2018!!"} {
			t.Errorf("fullList=%v first cred = %v, want crawluser:Server2018!!", full, creds[0])
		}
	}
}
