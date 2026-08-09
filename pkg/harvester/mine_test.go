package harvester

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return parsed
}

func TestExtractLinks_AbsoluteAndRelative(t *testing.T) {
	base := mustParse(t, "https://www.example.com/app/index.html")
	body := []byte(`
		<a href="/admin/panel">admin</a>
		<script src="/static/app.bundle.js"></script>
		fetch("/api/v2/users?id=1&amp;role=admin")
		<a href="https://api.example.com/graphql">api</a>
		<img src="/logo.png">
		<a href="https://evil.com/phish">offsite</a>
		<script src="//cdn.example.com/lib.js"></script>
	`)

	got := extractLinks(body, base, "example.com")

	for _, want := range []string{
		"https://www.example.com/admin/panel",
		"https://www.example.com/static/app.bundle.js",
		"https://api.example.com/graphql",
		"https://cdn.example.com/lib.js",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}

	// The query string must survive entity decoding intact — an `&amp;` left in
	// place would invent a parameter named "amp".
	if !slices.Contains(got, "https://www.example.com/api/v2/users?id=1&role=admin") {
		t.Errorf("entity-encoded query not decoded: %v", got)
	}

	for _, unwanted := range []string{
		"https://www.example.com/logo.png", // junk extension
		"https://evil.com/phish",           // out of scope
	} {
		if slices.Contains(got, unwanted) {
			t.Errorf("unexpectedly kept %q", unwanted)
		}
	}
}

// TestExtractLinks_RejectsJavaScriptRegexLiterals covers the false positives a
// framework bundle produces. Every literal below was observed coming out of the
// archived copies of Angular 1.7.7 and React DOM, and each one resolved to a
// plausible-looking endpoint that has never existed on the target.
func TestExtractLinks_RejectsJavaScriptRegexLiterals(t *testing.T) {
	base := mustParse(t, "https://example.com/resources/js/app.js")
	body := []byte(`
		a.replace(/&/gi, "&amp;").replace(/</gi, "&lt;").replace(/=/gi, "");
		b.split(/,/gi); c.match(/@/gi); d.replace(/ /g,e); f.test(/:$/);
		var flags = '/g,'; var marker = '/$'; var wildcard = '/*';
		var suffix = '/e/i'; var single = '/g'; var under = '/_';
		var dots = '/..'; var closer = '/)';
	`)

	if got := extractLinks(body, base, "example.com"); len(got) != 0 {
		t.Errorf("expected no links from regex literals, got %v", got)
	}
}

// TestExtractLinks_KeepsRealPathsAlongsideRegexes guards the other direction:
// tightening the extractor must not cost the endpoints it exists to find.
func TestExtractLinks_KeepsRealPathsAlongsideRegexes(t *testing.T) {
	base := mustParse(t, "https://example.com/resources/js/app.js")
	body := []byte(`
		var clean = s.replace(/&/gi, "");
		fetch("/api/v3/internal");
		var route = '/my-account';
		import("/chunks/checkout.js");
	`)

	got := extractLinks(body, base, "example.com")

	for _, want := range []string{
		"https://example.com/api/v3/internal",
		"https://example.com/my-account",
		"https://example.com/chunks/checkout.js",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d links, want 3: %v", len(got), got)
	}
}

func TestLooksLikeRelativePath(t *testing.T) {
	tests := map[string]bool{
		"/admin":            true,
		"/api/v1/users":     true,
		"/a.js":             true,
		"/_next/static/x":   true,
		"//cdn.example.com": true,
		// Regex literals, framework sentinels and flags.
		"/g":     false,
		"/e/i":   false,
		"/$":     false,
		"/*":     false,
		"/:$/":   false,
		"/..":    false,
		"/)":     false,
		"/ /g":   false,
		"/x/gim": false,
		"/":      false,
		"":       false,
		"admin":  false,
		"//":     false,
	}

	for candidate, want := range tests {
		if got := looksLikeRelativePath(candidate); got != want {
			t.Errorf("looksLikeRelativePath(%q) = %v, want %v", candidate, got, want)
		}
	}
}

func TestCleanCandidate(t *testing.T) {
	tests := map[string]string{
		"/a?x=1&amp;y=2": "/a?x=1&y=2",
		"  /a  ":         "/a",
		"/a,":            "/a",
		"/a).":           "/a",
		`/a\`:            "/a",
		"/g,":            "/g",
	}

	for in, want := range tests {
		if got := cleanCandidate(in); got != want {
			t.Errorf("cleanCandidate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractLinks_DropsArchiveHosts(t *testing.T) {
	base := mustParse(t, "https://example.com/")
	body := []byte(`<a href="https://web.archive.org/web/2020/https://example.com/x">replay</a>`)

	if got := extractLinks(body, base, "example.com"); len(got) != 0 {
		t.Errorf("expected archive host to be dropped, got %v", got)
	}
}

func TestExtractLinks_RespectsPerBodyCap(t *testing.T) {
	base := mustParse(t, "https://example.com/")

	var body bytes.Buffer
	for i := range mineMaxLinksPerBody * 2 {
		_, _ = fmt.Fprintf(&body, `<a href="https://example.com/p%d">x</a>`, i)
	}

	if got := extractLinks(body.Bytes(), base, "example.com"); len(got) > mineMaxLinksPerBody {
		t.Errorf("got %d links, want at most %d", len(got), mineMaxLinksPerBody)
	}
}

func TestHostInScope(t *testing.T) {
	tests := []struct {
		host, domain string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"api.example.com", "example.com", true},
		{"a.b.example.com", "example.com", true},
		{"example.com.", "example.com", true},
		{"EXAMPLE.com", "example.com", true},
		// The classic substring bug: this host merely ends with the domain.
		{"notexample.com", "example.com", false},
		{"example.com.evil.net", "example.com", false},
		{"web.archive.org", "archive.org", false},
		{"", "example.com", false},
		{"example.com", "", false},
	}

	for _, tt := range tests {
		if got := hostInScope(tt.host, tt.domain); got != tt.want {
			t.Errorf("hostInScope(%q, %q) = %v, want %v", tt.host, tt.domain, got, tt.want)
		}
	}
}

func TestParseRobots(t *testing.T) {
	base := mustParse(t, "https://example.com/robots.txt")
	body := []byte(`# comment
User-agent: *
Disallow: /admin/
Disallow: /internal/*.php
Disallow: /
Allow: /public/reports
Disallow:
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/news-sitemap.xml.gz
`)

	paths, sitemaps := parseRobots(body, base)

	for _, want := range []string{
		"https://example.com/admin/",
		"https://example.com/public/reports",
	} {
		if !slices.Contains(paths, want) {
			t.Errorf("missing path %q in %v", want, paths)
		}
	}

	// A wildcard names a set, so only the literal prefix before it is fetchable.
	if !slices.Contains(paths, "https://example.com/internal/") {
		t.Errorf("wildcard pattern not reduced to its prefix: %v", paths)
	}
	// `Disallow: /` is the whole site, which is not an endpoint.
	if slices.Contains(paths, "https://example.com/") {
		t.Errorf("bare root should not be emitted: %v", paths)
	}

	if len(sitemaps) != 2 {
		t.Errorf("got %d sitemaps, want 2: %v", len(sitemaps), sitemaps)
	}
}

func TestRobotsPathPrefix(t *testing.T) {
	tests := map[string]string{
		"/admin/":         "/admin/",
		"/internal/*.php": "/internal/",
		"/x$":             "/x",
		"/":               "",
		"":                "",
		"*":               "",
		"relative/path":   "",
	}

	for in, want := range tests {
		if got := robotsPathPrefix(in); got != want {
			t.Errorf("robotsPathPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSitemap(t *testing.T) {
	base := mustParse(t, "https://example.com/sitemap.xml")
	body := []byte(`<?xml version="1.0"?>
<urlset>
  <url><loc>https://example.com/a</loc></url>
  <url><loc>https://shop.example.com/b?x=1</loc></url>
  <url><loc>https://elsewhere.net/c</loc></url>
  <url><loc>https://example.com/logo.png</loc></url>
</urlset>`)

	got := parseSitemap(body, base, "example.com")

	if !slices.Contains(got, "https://example.com/a") || !slices.Contains(got, "https://shop.example.com/b?x=1") {
		t.Errorf("missing in-scope entries: %v", got)
	}
	if slices.Contains(got, "https://elsewhere.net/c") {
		t.Errorf("out-of-scope entry kept: %v", got)
	}
	if slices.Contains(got, "https://example.com/logo.png") {
		t.Errorf("static asset kept: %v", got)
	}
}

func TestSelectMineTargets_PrioritisesScriptsAndDedupesByPath(t *testing.T) {
	rows := []cdxRow{
		{URL: "https://example.com/page", MIME: "text/html", Status: "200"},
		{URL: "https://example.com/page?a=1", MIME: "text/html", Status: "200"},
		{URL: "https://example.com/app.js", MIME: "application/javascript", Status: "200"},
		{URL: "https://example.com/data.json", MIME: "application/json", Status: "200"},
		{URL: "https://example.com/style.css", MIME: "text/css", Status: "200"},
		{URL: "https://example.com/gone", MIME: "text/html", Status: "404"},
		{URL: "https://example.com/photo.png", MIME: "image/png", Status: "200"},
	}

	got := selectMineTargets(rows, 10)

	var urls []string
	for _, row := range got {
		urls = append(urls, row.URL)
	}

	if len(got) != 3 {
		t.Fatalf("got %d targets, want 3: %v", len(got), urls)
	}
	// A bundle names every route the front end can reach, so it goes first.
	if got[0].URL != "https://example.com/app.js" {
		t.Errorf("expected the script first, got %v", urls)
	}
	if slices.Contains(urls, "https://example.com/page?a=1") {
		t.Errorf("query-string variant should collapse into its endpoint: %v", urls)
	}
	for _, unwanted := range []string{
		"https://example.com/style.css",
		"https://example.com/gone",
		"https://example.com/photo.png",
	} {
		if slices.Contains(urls, unwanted) {
			t.Errorf("unexpectedly selected %q", unwanted)
		}
	}
}

func TestSelectMineTargets_RespectsLimit(t *testing.T) {
	var rows []cdxRow
	for i := range 100 {
		rows = append(rows, cdxRow{
			URL:    fmt.Sprintf("https://example.com/p%d", i),
			MIME:   "text/html",
			Status: "200",
		})
	}

	if got := selectMineTargets(rows, 5); len(got) != 5 {
		t.Errorf("got %d targets, want 5", len(got))
	}
	if got := selectMineTargets(rows, 0); got != nil {
		t.Errorf("expected nil for a zero limit, got %v", got)
	}
}

func TestDecompress(t *testing.T) {
	plain := []byte("not compressed")
	if got := decompress(plain); !bytes.Equal(got, plain) {
		t.Errorf("plain body altered: %q", got)
	}

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte("<loc>https://example.com/a</loc>")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if got := decompress(buf.Bytes()); !strings.Contains(string(got), "https://example.com/a") {
		t.Errorf("gzip body not inflated: %q", got)
	}
}

func TestIsRobotsAndSitemapURL(t *testing.T) {
	if !isRobotsURL("https://example.com/robots.txt") {
		t.Error("robots.txt not recognised")
	}
	if isRobotsURL("https://example.com/robots.txt.bak") {
		t.Error("robots.txt.bak wrongly recognised")
	}
	for _, want := range []string{
		"https://example.com/sitemap.xml",
		"https://example.com/news-sitemap.xml.gz",
		"https://example.com/sitemap_index.xml",
	} {
		if !isSitemapURL(want) {
			t.Errorf("sitemap not recognised: %s", want)
		}
	}
	if isSitemapURL("https://example.com/page.html") {
		t.Error("non-sitemap wrongly recognised")
	}
}
