package jsvendor

import "testing"

func TestIsCDNDomain(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"cdn.jsdelivr.net", true},
		{"unpkg.com", true},
		{"www.googletagmanager.com", true},
		{"sub.cdnjs.cloudflare.com", true}, // suffix match
		{"CDN.JSDELIVR.NET", true},         // case-insensitive
		{"app.target.com", false},
		{"api.example.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsCDNDomain(c.host); got != c.want {
			t.Errorf("IsCDNDomain(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestIsLibraryFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/assets/jquery.min.js", true},
		{"/js/gtag.js", true},
		{"/vendor/hcaptcha.js", true},
		{"/static/chart.min.js", true},
		{"/static/chunks/app-1a2b.js", false},   // first-party bundle
		{"/_next/static/chunks/main.js", false}, // first-party
		{"/api/data.js", false},
	}
	for _, c := range cases {
		if got := IsLibraryFile(c.path); got != c.want {
			t.Errorf("IsLibraryFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestShouldSkipJSPathExtraction(t *testing.T) {
	// CDN host → skip regardless of path.
	if !ShouldSkipJSPathExtraction("cdn.jsdelivr.net", "/npm/app/dist/bundle.min.js") {
		t.Error("CDN-hosted script should be skipped")
	}
	// Library filename on a first-party host → skip.
	if !ShouldSkipJSPathExtraction("target.com", "/static/gtag.js") {
		t.Error("analytics filename should be skipped")
	}
	// First-party app bundle → do not skip.
	if ShouldSkipJSPathExtraction("target.com", "/_next/static/chunks/app.js") {
		t.Error("first-party app bundle should not be skipped")
	}
}
