package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func TestFindingHostKey(t *testing.T) {
	cases := []struct {
		name string
		f    *database.Finding
		want string
	}{
		{"url", &database.Finding{URL: "https://api.example.com:8443/v1/users"}, "https://api.example.com:8443"},
		{"scheme-defaulted-from-matched", &database.Finding{MatchedAt: []string{"//host.example/x"}}, "http://host.example"},
		{"bare-hostname", &database.Finding{Hostname: "host.example"}, "host.example"},
		{"repo-fallback", &database.Finding{RepoName: "github.com/acme/app"}, "github.com/acme/app"},
		{"unknown", &database.Finding{}, "(unknown)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, findingHostKey(tc.f))
		})
	}
}

func TestFindingPathPrefix(t *testing.T) {
	cases := []struct {
		name string
		f    *database.Finding
		want string
	}{
		{"first-segment", &database.Finding{URL: "http://x/api/users/1"}, "/api"},
		{"root", &database.Finding{URL: "http://x/"}, "/"},
		{"from-matched-at", &database.Finding{MatchedAt: []string{"http://x/admin/panel"}}, "/admin"},
		{"bare-path-matched", &database.Finding{MatchedAt: []string{"/foo/bar"}}, "/foo"},
		{"source-file-fallback", &database.Finding{SourceFile: "src/main.go"}, "src/main.go"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, findingPathPrefix(tc.f))
		})
	}
}

func TestPocURLFromRequest(t *testing.T) {
	base := "https://x.example/setup/page?source=BASE"
	cases := []struct {
		name    string
		rawReq  string
		baseLoc string
		want    string
	}{
		{
			name:    "same-endpoint-payload-query-upgraded",
			rawReq:  "GET /setup/page?source=%22%5Ealert%281%29%5E%22 HTTP/1.1\r\nHost: x.example\r\n\r\n",
			baseLoc: base,
			want:    "https://x.example/setup/page?source=%22%5Ealert%281%29%5E%22",
		},
		{
			name:    "post-to-get-conversion-same-path",
			rawReq:  "GET /setup/page?source=PAYLOAD HTTP/1.1\nHost: x.example\n\n",
			baseLoc: "https://x.example/setup/page",
			want:    "https://x.example/setup/page?source=PAYLOAD",
		},
		{
			name:    "different-host-ignored",
			rawReq:  "GET /api/config HTTP/1.1\r\nHost: other.example\r\n\r\n",
			baseLoc: "https://cognito.example/pool",
			want:    "",
		},
		{
			name:    "different-path-ignored",
			rawReq:  "GET /other/place?x=1 HTTP/1.1\r\nHost: x.example\r\n\r\n",
			baseLoc: base,
			want:    "",
		},
		{
			name:    "identical-to-base-no-change",
			rawReq:  "GET /setup/page?source=BASE HTTP/1.1\r\nHost: x.example\r\n\r\n",
			baseLoc: base,
			want:    "",
		},
		{"empty-request", "", base, ""},
		{"malformed-request-line", "not-a-request-line", base, ""},
		{"empty-base", "GET /x HTTP/1.1\r\n\r\n", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pocURLFromRequest(tc.rawReq, tc.baseLoc))
		})
	}
}

func TestFindingDisplayLocations(t *testing.T) {
	// Single-location injection finding: the shown URL is upgraded to the PoC URL
	// carried in the request, not the base matched_at.
	xss := &database.Finding{
		MatchedAt: []string{"https://x.example/p?source=BASE"},
		Request:   "GET /p?source=%3Cscript%3E HTTP/1.1\r\nHost: x.example\r\n\r\n",
	}
	assert.Equal(t, []string{"https://x.example/p?source=%3Cscript%3E"}, findingDisplayLocations(xss))

	// Grouped multi-URL finding: never upgraded — every matched location is kept.
	grouped := &database.Finding{
		MatchedAt: []string{"https://x.example/a", "https://x.example/b"},
		Request:   "GET /a?x=1 HTTP/1.1\r\nHost: x.example\r\n\r\n",
	}
	assert.Equal(t, []string{"https://x.example/a", "https://x.example/b"}, findingDisplayLocations(grouped))

	// Request targeting a different endpoint: keep the matched_at location.
	crossHost := &database.Finding{
		MatchedAt: []string{"https://cognito.example/pool"},
		Request:   "GET /api/config HTTP/1.1\r\nHost: app.example\r\n\r\n",
	}
	assert.Equal(t, []string{"https://cognito.example/pool"}, findingDisplayLocations(crossHost))

	// No matched_at, no request: falls back to the finding's URL value.
	bare := &database.Finding{URL: "https://x.example/only"}
	assert.Equal(t, []string{"https://x.example/only"}, findingDisplayLocations(bare))
}

func TestColorSeverityTag(t *testing.T) {
	assert.Equal(t, "[HIGH]", terminal.StripANSI(colorSeverityTag("high")))
	assert.Equal(t, "[CRITICAL]", terminal.StripANSI(colorSeverityTag("critical")))
	// Unknown severity is passed through, still bracketed/uppercased.
	assert.Equal(t, "[WHATEVER]", terminal.StripANSI(colorSeverityTag("whatever")))
}

func TestFormatFindingGroupLeaf(t *testing.T) {
	g := &findingPathGroup{rep: &database.Finding{Severity: "high", ModuleName: "sql-injection-error", ModuleShort: "Error-based SQLi in id param", Confidence: "firm", ModuleType: database.ModuleTypeActive}}
	assert.Equal(t, "[HIGH] sql-injection-error — Error-based SQLi in id param (firm, active)", terminal.StripANSI(formatFindingGroupLeaf(g)))

	// Falls back to the representative finding's description when no short desc,
	// and shows the passive module type beside the confidence.
	g2 := &findingPathGroup{rep: &database.Finding{Severity: "low", ModuleName: "m", Confidence: "tentative", Description: "desc here", ModuleType: database.ModuleTypePassive}}
	assert.Equal(t, "[LOW] m — desc here (tentative, passive)", terminal.StripANSI(formatFindingGroupLeaf(g2)))

	// No module type recorded → just the confidence, unchanged.
	g3 := &findingPathGroup{rep: &database.Finding{Severity: "low", ModuleName: "m", Confidence: "firm", Description: "d"}}
	assert.Equal(t, "[LOW] m — d (firm)", terminal.StripANSI(formatFindingGroupLeaf(g3)))
}

func TestGroupPathFindings_CollapsesTitleAndDedupsURLs(t *testing.T) {
	findings := []*database.Finding{
		{ID: 41, Severity: "low", Confidence: "firm", ModuleName: "reverse-tabnabbing", ModuleShort: "target=_blank",
			MatchedAt: []string{"https://x/a"}},
		{ID: 500, Severity: "low", Confidence: "firm", ModuleName: "reverse-tabnabbing", ModuleShort: "target=_blank",
			MatchedAt: []string{"https://x/b", "https://x/c"}},
		{ID: 9, Severity: "critical", Confidence: "certain", ModuleName: "auth-bypass", ModuleShort: "open",
			MatchedAt: []string{"https://x/admin"}},
	}
	groups := groupPathFindings(findings)

	// Two distinct titles → two groups, critical first.
	assert.Len(t, groups, 2)
	assert.Equal(t, "auth-bypass", groups[0].rep.ModuleName)
	assert.Equal(t, "reverse-tabnabbing", groups[1].rep.ModuleName)

	// The reverse-tabnabbing group collapses both findings and lists all 3 URLs,
	// each carrying its reporting finding id, ordered by id.
	tab := groups[1]
	assert.Equal(t, []urlRef{
		{url: "https://x/a", id: 41},
		{url: "https://x/b", id: 500},
		{url: "https://x/c", id: 500},
	}, tab.urls)
}

func TestDedupURLRefs(t *testing.T) {
	got := dedupURLRefs([]urlRef{
		{url: "https://x/a", id: 7},
		{url: "https://x/a", id: 3}, // duplicate URL — keep lowest id
		{url: "https://x/b", id: 5},
	})
	assert.Equal(t, []urlRef{
		{url: "https://x/a", id: 3},
		{url: "https://x/b", id: 5},
	}, got)
}

func TestDisplayFindingTree_EndToEnd(t *testing.T) {
	db := newExportTestDB(t)
	findings := []*database.Finding{
		{ID: 1, ProjectUUID: "p", Severity: "critical", Confidence: "certain",
			ModuleName: "auth-bypass", ModuleShort: "Admin panel accessible",
			URL: "http://a.example/admin", MatchedAt: []string{"http://a.example/admin"}, FindingHash: "h1"},
		// Two same-title LOW findings under /as → collapse to one leaf, 3 URL lines.
		{ID: 41, ProjectUUID: "p", Severity: "low", Confidence: "firm",
			ModuleName: "reverse-tabnabbing", ModuleShort: "target=_blank without rel=noopener",
			URL: "http://a.example/as/one", MatchedAt: []string{"http://a.example/as/one"}, FindingHash: "h41"},
		{ID: 500, ProjectUUID: "p", Severity: "low", Confidence: "firm",
			ModuleName: "reverse-tabnabbing", ModuleShort: "target=_blank without rel=noopener",
			URL: "http://a.example/as/two", MatchedAt: []string{"http://a.example/as/two", "http://a.example/as/three"}, FindingHash: "h500"},
	}

	out := terminal.StripANSI(captureStdout(t, func() {
		_ = displayFindingTree(db, context.Background(), findings, int64(len(findings)))
	}))

	// Host grouping with per-host counts.
	assert.Contains(t, out, "└── http://a.example (3 findings) [C:1 L:2]")
	// Collapsed title appears exactly once under /as (deduped).
	assert.Equal(t, 1, strings.Count(out, "reverse-tabnabbing"), "module leaf should be deduped to one line")
	// All three affected URLs are listed on their own lines with the reporting id.
	assert.Contains(t, out, "→ http://a.example/as/one  #41")
	assert.Contains(t, out, "→ http://a.example/as/two  #500")
	assert.Contains(t, out, "→ http://a.example/as/three  #500")
	// Critical leaf still renders.
	assert.Contains(t, out, "[CRITICAL] auth-bypass — Admin panel accessible (certain)")
}
