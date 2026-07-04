package httpmsg

import (
	"net/http"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"Example.com":         "example.com",
		"example.com:8443":    "example.com",
		"  WWW.Example.com  ": "www.example.com",
		"127.0.0.1:8080":      "127.0.0.1",
		"":                    "",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFlattenCookiesForHost(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "cf_clearance", Value: "abc", Domain: ".example.com"},
		{Name: "session", Value: "xyz", Domain: "www.example.com"},
		{Name: "other", Value: "1", Domain: "unrelated.org"}, // different host → dropped
		{Name: "cf_clearance", Value: "dup", Domain: ".example.com"}, // dup name → first wins
		{Name: "", Value: "skip", Domain: ".example.com"},            // no name → skipped
	}

	got := FlattenCookiesForHost("www.example.com", cookies)
	want := "cf_clearance=abc; session=xyz"
	if got != want {
		t.Fatalf("FlattenCookiesForHost = %q, want %q", got, want)
	}

	// A host the cookies do not apply to yields nothing.
	if got := FlattenCookiesForHost("evil.com", cookies); got != "" {
		t.Errorf("expected no cookies for unrelated host, got %q", got)
	}

	// Port on the host is stripped before matching.
	if got := FlattenCookiesForHost("www.example.com:443", cookies); got != want {
		t.Errorf("port-bearing host = %q, want %q", got, want)
	}
}

func TestFlattenCookiesForHost_HostOnlyCookie(t *testing.T) {
	// A blank Domain is a host-only cookie: it applies to whatever host we scope
	// to (the browser only returns it for hosts it was set on).
	cookies := []*http.Cookie{{Name: "hostonly", Value: "1", Domain: ""}}
	if got := FlattenCookiesForHost("app.test", cookies); got != "hostonly=1" {
		t.Errorf("host-only cookie = %q, want %q", got, "hostonly=1")
	}
}

func TestMergeCookieHeaders(t *testing.T) {
	cases := []struct {
		name           string
		existing       string
		carried        string
		want           string
	}{
		{"empty existing", "", "cf=1; s=2", "cf=1; s=2"},
		{"empty carried", "a=1", "", "a=1"},
		{"add missing only", "a=1; b=2", "cf=1; a=9", "a=1; b=2; cf=1"},
		{"existing always wins", "sess=keep", "sess=drop; cf=1", "sess=keep; cf=1"},
		{"trailing semicolon existing", "a=1; ", "cf=1", "a=1; cf=1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MergeCookieHeaders(c.existing, c.carried); got != c.want {
				t.Errorf("MergeCookieHeaders(%q, %q) = %q, want %q", c.existing, c.carried, got, c.want)
			}
		})
	}
}
