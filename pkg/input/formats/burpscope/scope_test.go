package burpscope

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rule builds an enabled advanced-mode rule for the given host/protocol.
func rule(protocol, host, port string) Rule {
	on := true
	return Rule{Enabled: &on, Protocol: protocol, Host: host, Port: port, File: `^/.*`}
}

func writeScope(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

const twoHostScope = `{"target":{"scope":{"advanced_mode":true,
  "include":[
    {"enabled":true,"file":"^/.*","host":"^www\\.example\\.com$","port":"^80$","protocol":"http"},
    {"enabled":true,"file":"^/.*","host":"^www\\.example\\.com$","port":"^443$","protocol":"https"},
    {"enabled":true,"file":"^/.*","host":"^.*\\.example\\.org$","port":"^443$","protocol":"https"},
    {"enabled":true,"file":"^/.*","host":"^api\\.example\\.net$","port":"^443$","protocol":"https"}
  ],
  "exclude":[
    {"enabled":true,"file":"^/.*","host":"^api\\.example\\.net$","port":"^443$","protocol":"https"}
  ]}}}`

func TestExpand_LiteralHostsHTTPCollapsedIntoHTTPS(t *testing.T) {
	res := Expand(&Scope{Include: []Rule{
		rule("http", `^www\.example\.com$`, `^80$`),
		rule("https", `^www\.example\.com$`, `^443$`),
	}})

	// The http entry of a host that is also in scope over https is a redirect in
	// practice; scanning both doubles the work for one target.
	assert.Equal(t, []string{"https://www.example.com/"}, res.URLs)
	assert.Equal(t, 1, res.CollapsedHTTP)
}

func TestExpand_HTTPOnlyHostKept(t *testing.T) {
	res := Expand(&Scope{Include: []Rule{rule("http", `^legacy\.example\.com$`, `^80$`)}})

	assert.Equal(t, []string{"http://legacy.example.com/"}, res.URLs)
	assert.Zero(t, res.CollapsedHTTP)
}

func TestExpand_NonDefaultPortKeptInURL(t *testing.T) {
	res := Expand(&Scope{Include: []Rule{
		rule("https", `^www\.example\.com$`, `^8443$`),
		rule("http", `^www\.example\.com$`, `^8080$`),
	}})

	assert.Equal(t, []string{"https://www.example.com:8443/", "http://www.example.com:8080/"}, res.URLs)
	// An explicit non-default port is a different service, so it survives the
	// https collapse.
	assert.Zero(t, res.CollapsedHTTP)
}

func TestExpand_WildcardHostReportedNotGuessed(t *testing.T) {
	res := Expand(&Scope{Include: []Rule{
		rule("https", `^.*\.example\.com$`, `^443$`),
		rule("https", `^v.*\.example\.com$`, `^443$`),
	}})

	// Inventing example.com from "*.example.com" would send traffic at a host
	// the scope never listed.
	assert.Empty(t, res.URLs)
	assert.ElementsMatch(t, []string{"*.example.com", "v*.example.com"}, res.WildcardHosts)
}

func TestExpand_ExcludeRuleDropsTarget(t *testing.T) {
	res := Expand(&Scope{
		Include: []Rule{
			rule("https", `^www\.example\.com$`, `^443$`),
			rule("https", `^admin\.example\.com$`, `^443$`),
		},
		Exclude: []Rule{rule("https", `^admin\.example\.com$`, `^443$`)},
	})

	assert.Equal(t, []string{"https://www.example.com/"}, res.URLs)
	assert.Equal(t, 1, res.Excluded)
}

func TestExpand_ExcludeMatchesOnPathAndProtocol(t *testing.T) {
	inc := rule("https", `^www\.example\.com$`, `^443$`)
	inc.File = `^/admin/.*`

	exc := rule("http", `^www\.example\.com$`, `^80$`)
	res := Expand(&Scope{Include: []Rule{inc}, Exclude: []Rule{exc}})

	// The exclude covers http only, so the https include survives.
	assert.Equal(t, []string{"https://www.example.com/admin/"}, res.URLs)
	assert.Zero(t, res.Excluded)
}

func TestExpand_DisabledRuleSkipped(t *testing.T) {
	off := false
	r := rule("https", `^www\.example\.com$`, `^443$`)
	r.Enabled = &off

	res := Expand(&Scope{Include: []Rule{r}})
	assert.Empty(t, res.URLs)
	assert.Equal(t, 1, res.Disabled)
}

func TestExpand_MissingEnabledDefaultsOn(t *testing.T) {
	res := Expand(&Scope{Include: []Rule{{Protocol: "https", Host: `^www\.example\.com$`, Port: `^443$`, File: `^/.*`}}})
	assert.Equal(t, []string{"https://www.example.com/"}, res.URLs)
	assert.Zero(t, res.Disabled)
}

func TestExpand_ProtocolAnyResolvedByPort(t *testing.T) {
	res := Expand(&Scope{Include: []Rule{rule("any", `^www\.example\.com$`, `^443$`)}})
	assert.Equal(t, []string{"https://www.example.com/"}, res.URLs)

	both := Expand(&Scope{Include: []Rule{rule("any", `^www\.example\.com$`, `^8080$`)}})
	assert.Equal(t, []string{"http://www.example.com:8080/", "https://www.example.com:8080/"}, both.URLs)
}

func TestExpand_PathPrefixFromFileRule(t *testing.T) {
	r := rule("https", `^api\.example\.com$`, `^443$`)
	r.File = `^/v2/.*`

	res := Expand(&Scope{Include: []Rule{r}})
	assert.Equal(t, []string{"https://api.example.com/v2/"}, res.URLs)
}

func TestExpand_SimpleModePrefixRules(t *testing.T) {
	on := true
	res := Expand(&Scope{
		AdvancedMode: false,
		Include: []Rule{
			{Enabled: &on, Prefix: "https://www.example.com/app/"},
			{Enabled: &on, Prefix: "https://admin.example.com:8443/"},
		},
		Exclude: []Rule{{Enabled: &on, Prefix: "https://admin.example.com:8443/"}},
	})

	assert.Equal(t, []string{"https://www.example.com/app/"}, res.URLs)
	assert.Equal(t, 1, res.Excluded)
}

func TestExpand_DuplicateRulesDeduped(t *testing.T) {
	res := Expand(&Scope{Include: []Rule{
		rule("https", `^www\.example\.com$`, `^443$`),
		rule("https", `^www\.example\.com$`, `^443$`),
	}})
	assert.Equal(t, []string{"https://www.example.com/"}, res.URLs)
}

func TestExpand_UncompilableExcludeIsSkippedNotFatal(t *testing.T) {
	bad := rule("https", `^(unclosed\.example\.com$`, `^443$`)
	res := Expand(&Scope{
		Include: []Rule{rule("https", `^www\.example\.com$`, `^443$`)},
		Exclude: []Rule{bad},
	})
	assert.Equal(t, []string{"https://www.example.com/"}, res.URLs)
}

func TestSniff(t *testing.T) {
	assert.True(t, Sniff([]byte(twoHostScope)))
	assert.False(t, Sniff([]byte(`{"log":{"entries":[{"request":{"url":"https://example.com/"}}]}}`)))
	assert.False(t, Sniff([]byte(`{"target":{"scope":{"include":[]}}}`)))
	assert.False(t, Sniff([]byte(`not json`)))
	assert.False(t, Sniff([]byte(`{"target":{"scope":`)))
}

func TestSniffFile(t *testing.T) {
	assert.True(t, SniffFile(writeScope(t, twoHostScope)))
	assert.False(t, SniffFile(writeScope(t, "https://example.com/\nhttps://example.org/\n")))
	assert.False(t, SniffFile(filepath.Join(t.TempDir(), "missing.json")))
	assert.False(t, SniffFile(t.TempDir()))
}

func TestTargetURLs_EndToEnd(t *testing.T) {
	res, err := TargetURLs(writeScope(t, twoHostScope))
	require.NoError(t, err)

	assert.Equal(t, []string{"https://www.example.com/"}, res.URLs)
	assert.Equal(t, []string{"*.example.org"}, res.WildcardHosts)
	assert.Equal(t, 1, res.Excluded)
	assert.Equal(t, 1, res.CollapsedHTTP)
	assert.Equal(t, "1 target · 1 wildcard host skipped · 1 http→https collapsed · 1 excluded", res.Summary())
	assert.Equal(t, "*.example.org", res.WildcardSample(3))
}

// TestWildcardSample keeps the wildcard list to a display-sized sample — a
// scope with 17 of them would otherwise turn the notice into a paragraph.
func TestWildcardSample(t *testing.T) {
	res := &Result{WildcardHosts: []string{"*.c.example.com", "*.a.example.com", "*.b.example.com", "*.d.example.com"}}

	assert.Equal(t, "*.a.example.com, *.b.example.com, +2", res.WildcardSample(2))
	assert.Equal(t, "*.a.example.com, *.b.example.com, *.c.example.com, *.d.example.com", res.WildcardSample(4))
	assert.Equal(t, "*.a.example.com, *.b.example.com, *.c.example.com, *.d.example.com", res.WildcardSample(0))
	assert.Empty(t, (&Result{}).WildcardSample(3))
}

func TestLoad_Errors(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	assert.Error(t, err)

	_, err = Load(writeScope(t, `{"target":{"scope":{"include":[]}}}`))
	assert.ErrorContains(t, err, "no target.scope rules")

	_, err = Load(writeScope(t, `{`))
	assert.ErrorContains(t, err, "failed to parse")
}

// TestStats keeps the tally structured: the console colours each count, so the
// number must stay separable from its label rather than being pre-rendered.
func TestStats(t *testing.T) {
	res := &Result{
		URLs:          []string{"https://www.example.com/", "https://api.example.com/"},
		WildcardHosts: []string{"*.example.org"},
		CollapsedHTTP: 3,
		Excluded:      1,
		Disabled:      2,
	}

	assert.Equal(t, []Stat{
		{2, "targets"},
		{1, "wildcard host skipped"},
		{3, "http→https collapsed"},
		{1, "excluded"},
		{2, "disabled"},
	}, res.Stats())

	// A clean expansion reports only the target count.
	assert.Equal(t, []Stat{{1, "target"}}, (&Result{URLs: []string{"https://www.example.com/"}}).Stats())
	assert.Equal(t, []Stat{{0, "targets"}}, (&Result{}).Stats())
}
