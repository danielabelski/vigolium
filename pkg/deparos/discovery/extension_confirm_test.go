package discovery

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/config"
)

// confirmTestConfig builds an engine config with the extension-confirm pipeline
// enabled. TestObserved is left off so confirmExtension does not try to generate
// dynamic tasks (which need storage); the tests assert the confirmation decision
// itself (callback + confirmed/observed state).
func confirmTestConfig(startURL string, probe bool) *config.Config {
	return &config.Config{
		Target: config.TargetConfig{
			StartURL:  startURL,
			Mode:      config.ModeFilesAndDirs,
			Recursion: config.RecursionConfig{Enabled: true, MaxDepth: 16},
		},
		Filenames: config.FilenameConfig{Wordlists: config.WordlistConfig{}},
		Extensions: config.ExtensionConfig{
			ConfirmRequired:       true,
			ConfirmViaObserved:    true,
			ConfirmViaFingerprint: true,
			ConfirmViaProbe:       probe,
			Candidates:            []string{"php", "aspx", "ashx", "jsp", "jspx", "do", "action", "cgi", "cfm"},
			ProbeFilenames:        []string{"index"},
			TestObserved:          false,
			TestNoExtension:       true,
		},
		Engine: config.EngineConfig{
			CaseSensitivity:  config.CaseInsensitive,
			DiscoveryThreads: 4,
			Timeout:          30 * time.Second,
		},
	}
}

func TestNormalizeExt(t *testing.T) {
	cases := map[string]string{
		"php":       "php",
		".php":      "php",
		"..PHP":     "php",
		"  .Action": "action",
		"ASPX ":     "aspx",
		"":          "",
		".":         "",
	}
	for in, want := range cases {
		assert.Equal(t, want, normalizeExt(in), "normalizeExt(%q)", in)
	}
}

func TestStartURLDirectory(t *testing.T) {
	cases := map[string]string{
		"http://h/admin.php":         "/",
		"http://h/app/index.php?x=1": "/app/",
		"http://h/app/v1/":           "/app/v1/",
		"http://h":                   "/",
		"http://h/a/b/c.jsp#frag":    "/a/b/",
	}
	for in, wantPath := range cases {
		u, err := url.Parse(in)
		require.NoError(t, err)
		dir := startURLDirectory(u)
		require.NotNil(t, dir)
		assert.Equal(t, wantPath, dir.Path, "startURLDirectory(%q).Path", in)
		assert.Empty(t, dir.RawQuery)
		assert.Empty(t, dir.Fragment)
	}
}

func TestConfirmExtension_DedupCallbackAndCandidateGate(t *testing.T) {
	engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/", false))
	require.NoError(t, err)
	defer engine.Stop()

	var events []ExtensionConfirmEvent
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) {
		events = append(events, ev)
	})

	// First confirmation succeeds.
	assert.True(t, engine.confirmExtension("php", "test", "detail", 0))
	assert.True(t, engine.isExtensionConfirmed("php"))
	assert.True(t, engine.observedExtensions.Contains([]byte("php")), "php should be in observed extensions")

	// Repeat confirmation (with dotted/upper form) is a no-op.
	assert.False(t, engine.confirmExtension(".PHP", "test", "again", 0))

	// Non-candidate extension is rejected outright.
	assert.False(t, engine.confirmExtension("html", "test", "", 0))
	assert.False(t, engine.isExtensionConfirmed("html"))

	// Exactly one callback fired (the first php confirmation).
	require.Len(t, events, 1)
	assert.Equal(t, "php", events[0].Extension)
	assert.Equal(t, "test", events[0].Source)
}

// TestConfirmExtension_OneServerStackCatchAllGuard proves the catch-all guard:
// once one server-side stack family is confirmed, a confirmation for a *different*
// family is refused (a single app serves exactly one stack — confirming several at
// once is the catch-all/SPA-gateway signature from scim-bridge2.foundation.azure).
// Same-family extensions and non-stack candidates are unaffected.
func TestConfirmExtension_OneServerStackCatchAllGuard(t *testing.T) {
	// Genuine host: it 404s the nonce probes so the per-extension catch-all guard
	// clears every family and the one-stack conflict guard is what does the work.
	server := notFoundServer()
	defer server.Close()

	cfg := confirmTestConfig(server.URL, false)
	cfg.Extensions.Candidates = []string{
		"php", "php5", "aspx", "ashx", "jsp", "do", "action", "cgi", "cfm",
	}
	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	defer engine.Stop()

	// First stack family confirms.
	assert.True(t, engine.confirmExtension("php", "observed", "/a.php", 0))
	assert.True(t, engine.isExtensionConfirmed("php"))

	// Same family (php5) still confirms — not mutually exclusive.
	assert.True(t, engine.confirmExtension("php5", "observed", "/a.php5", 0))
	assert.True(t, engine.isExtensionConfirmed("php5"))

	// Every other server-side stack is refused once php is confirmed.
	for _, ext := range []string{"aspx", "ashx", "jsp", "do", "action", "cgi", "cfm"} {
		assert.False(t, engine.confirmExtension(ext, "observed", "/x."+ext, 0),
			"%s must be refused after php confirmed (catch-all guard)", ext)
		assert.False(t, engine.isExtensionConfirmed(ext),
			"%s must NOT be marked confirmed", ext)
	}
}

func TestServerStackFamily(t *testing.T) {
	cases := map[string]string{
		"php": "php", "php5": "php", "phtml": "php",
		"asp": "aspnet", "aspx": "aspnet", "ashx": "aspnet", "asmx": "aspnet",
		"jsp": "java", "jspx": "java", "jspa": "java", "do": "java", "action": "java",
		"cfm": "coldfusion", "cfml": "coldfusion",
		"cgi": "cgi", "pl": "cgi",
		// Non-stack extensions are exempt from the one-stack guard.
		"js": "", "json": "", "html": "", "txt": "", "": "",
	}
	for ext, want := range cases {
		assert.Equal(t, want, serverStackFamily(ext), "serverStackFamily(%q)", ext)
	}
}

func TestRedirectPreservesPath(t *testing.T) {
	cases := []struct {
		name           string
		original, dest string
		want           bool
	}{
		{"scheme upgrade same path", "http://h/PDC/ajaxreq.php", "https://h/PDC/ajaxreq.php", true},
		{"identical", "https://h/debug.cgi", "https://h/debug.cgi", true},
		{"same path added query", "https://h/x.do", "https://h/x.do?sso=1", true},
		{"trailing slash tolerated", "https://h/admin.jsp", "https://h/admin.jsp/", true},
		{"different path is a real reference", "https://h/foo.php", "https://h/login.jsp", false},
		{"different dir same file", "https://h/a/x.php", "https://h/b/x.php", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, redirectPreservesPath(tc.original, tc.dest))
		})
	}
}

func TestConfirmExtensionsFromHeaders_Fingerprint(t *testing.T) {
	tests := []struct {
		name     string
		header   http.Header
		wantExts []string
		noneExts []string
	}{
		{
			name:     "PHPSESSID ⇒ php",
			header:   http.Header{"Set-Cookie": {"PHPSESSID=abc; path=/"}},
			wantExts: []string{"php"},
			noneExts: []string{"aspx", "jsp"},
		},
		{
			name:     "JSESSIONID ⇒ jsp/jspx/do/action",
			header:   http.Header{"Set-Cookie": {"JSESSIONID=xyz; Path=/"}},
			wantExts: []string{"jsp", "jspx", "do", "action"},
			noneExts: []string{"php", "aspx"},
		},
		{
			name:     "ASP.NET_SessionId ⇒ aspx/ashx",
			header:   http.Header{"Set-Cookie": {"ASP.NET_SessionId=q; path=/"}},
			wantExts: []string{"aspx", "ashx"},
			noneExts: []string{"php", "jsp"},
		},
		{
			name:     "static site ⇒ nothing",
			header:   http.Header{"Server": {"nginx"}},
			noneExts: []string{"php", "aspx", "jsp"},
		},
	}

	// Genuine host that 404s the nonce probes, so the catch-all guard clears it and
	// the fingerprint-derived extensions confirm (keeps the test offline).
	server := notFoundServer()
	defer server.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := testEngineWithConfig(confirmTestConfig(server.URL, false))
			require.NoError(t, err)
			defer engine.Stop()

			engine.confirmExtensionsFromHeaders(tt.header.Get, tt.header.Values("Set-Cookie"), "test", 0)

			for _, e := range tt.wantExts {
				assert.True(t, engine.isExtensionConfirmed(e), "%s should be confirmed", e)
			}
			for _, e := range tt.noneExts {
				assert.False(t, engine.isExtensionConfirmed(e), "%s should NOT be confirmed", e)
			}
		})
	}
}

func TestConfirmStartURLExtensions_ObservedSeedExt(t *testing.T) {
	// Start URL is itself a .php file that was SERVED (2xx) ⇒ php confirmed via the
	// "observed" source. The host 404s the nonce probes, so the catch-all guard
	// clears it.
	server := notFoundServer()
	defer server.Close()

	engine, err := testEngineWithConfig(confirmTestConfig(server.URL+"/admin.php", false))
	require.NoError(t, err)
	defer engine.Stop()
	engine.startURLStatus = 200 // the seed .php was served

	var sources []string
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) {
		if ev.Extension == "php" {
			sources = append(sources, ev.Source)
		}
	})

	engine.confirmStartURLExtensions()

	assert.True(t, engine.isExtensionConfirmed("php"), "php should be confirmed from the .php start URL")
	require.NotEmpty(t, sources)
	assert.Equal(t, "observed", sources[0])
}

// TestConfirmStartURLExtensions_FingerprintGatedOnGenuineLanding proves the
// start-URL fingerprint source only fires on a genuine 2xx, non-login landing
// page. This is the orders-test.example.com regression: the root 302'd off-host
// to a Salesforce SSO page, yet PHP (php/php3/php4/php5/phtml) was "confirmed via
// fingerprint (PHP via start URL)" and a full *.php wordlist fuzz was queued on a
// host that serves no PHP at all. The observed/probe sources are unaffected.
func TestConfirmStartURLExtensions_FingerprintGatedOnGenuineLanding(t *testing.T) {
	// A header that fingerprints as PHP regardless of the response status.
	phpHeader := http.Header{"Set-Cookie": {"PHPSESSID=abc; path=/"}}

	cases := []struct {
		name    string
		status  int
		isLogin bool
		want    bool // php confirmed from the fingerprint?
	}{
		{"200 genuine app page confirms", 200, false, true},
		{"204 served confirms", 204, false, true},
		{"301 redirect skips", 301, false, false},
		{"302 off-host SSO bounce skips", 302, false, false},
		{"401 auth wall skips", 401, false, false},
		{"403 forbidden skips", 403, false, false},
		{"404 not found skips", 404, false, false},
		{"500 server error skips", 500, false, false},
		{"unknown status skips", 0, false, false},
		{"200 but login/SSO interstitial skips", 200, true, false},
	}

	// Genuine host that 404s the nonce probes: the catch-all guard clears it, so
	// the only thing under test is the genuine-landing gate on the fingerprint
	// source (keeps the test offline).
	server := notFoundServer()
	defer server.Close()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := testEngineWithConfig(confirmTestConfig(server.URL, false))
			require.NoError(t, err)
			defer engine.Stop()

			engine.startURLHeader = phpHeader
			engine.startURLStatus = tc.status
			engine.startURLIsLogin = tc.isLogin

			engine.confirmStartURLExtensions()

			assert.Equal(t, tc.want, engine.isExtensionConfirmed("php"),
				"php fingerprint confirmation for status=%d login=%v", tc.status, tc.isLogin)
		})
	}
}

// notFoundServer 404s every path — a genuine host that does not answer arbitrary
// routes, so the extension catch-all guard clears it and observed/fingerprint
// confirmations proceed. Used to keep the confirmation unit tests offline now that
// those sources run an active <nonce>.<ext> catch-all probe.
func notFoundServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
}

// catchAllServer 200s every path with a generic body — a modern SPA/CDN host that
// answers (and reflects) any route. The extension catch-all guard must flag it and
// suppress observed/fingerprint confirmations.
func catchAllServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>generic app shell for " + r.URL.Path + "</body></html>"))
	}))
}

// TestConfirmStartURLExtensions_ObservedSeedGatedOnServed is the session.hooli.com
// / www.hooli.com regression: recon seeds a known-probe path such as
// /Telerik.Web.UI.DialogHandler.aspx (404) or /overview/default.aspx (302) on a
// host that runs no ASP.NET. The observed start-URL source must NOT confirm .aspx
// off the ".aspx" suffix alone — only a served (2xx / 401 / 403) seed qualifies.
func TestConfirmStartURLExtensions_ObservedSeedGatedOnServed(t *testing.T) {
	// notFoundServer 404s the nonce probes so the catch-all guard is not the actor
	// under test here — the seed's own status is.
	server := notFoundServer()
	defer server.Close()

	cases := []struct {
		name   string
		status int
		want   bool
	}{
		{"200 served seed confirms", 200, true},
		{"204 served seed confirms", 204, true},
		{"401 auth wall confirms", 401, true},
		{"403 forbidden confirms", 403, true},
		{"301 redirect seed skips", 301, false},
		{"302 off-host bounce skips", 302, false},
		{"404 missing seed skips", 404, false},
		{"500 error seed skips", 500, false},
		{"unknown status skips", 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine, err := testEngineWithConfig(confirmTestConfig(server.URL+"/Telerik.Web.UI.DialogHandler.aspx", false))
			require.NoError(t, err)
			defer engine.Stop()
			engine.startURLStatus = tc.status

			engine.confirmStartURLExtensions()

			assert.Equal(t, tc.want, engine.isExtensionConfirmed("aspx"),
				"aspx observed confirmation for seed status=%d", tc.status)
		})
	}
}

// probeServer serves a real resource at /index.<ext> and 404s everything else,
// so the analyzer sees index.<ext> as distinct from the soft-404 baseline.
func probeServer(realPath string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == realPath {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>real application home page with unique content</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
}

func TestProbeCandidateExtensions_ConfirmsRealRoute(t *testing.T) {
	server := probeServer("/index.php")
	defer server.Close()

	engine, err := testEngineWithConfig(confirmTestConfig(server.URL, true))
	require.NoError(t, err)
	defer engine.Stop()
	engine.config.Extensions.Candidates = []string{"php"}

	var confirmed []string
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) {
		confirmed = append(confirmed, ev.Extension)
	})

	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	// Learn the soft-404 baseline first (initSession does this before probing in
	// production), so the wildcard differential can recognise the 404s.
	require.NoError(t, engine.learnBaselineFingerprints(u))
	engine.probeCandidateExtensions(startURLDirectory(u), 0)

	assert.True(t, engine.isExtensionConfirmed("php"), "php should be confirmed via probe of index.php")
	assert.Contains(t, confirmed, "php")
}

func TestProbeCandidateExtensions_CatchAllNotConfirmed(t *testing.T) {
	// Catch-all server: identical 200 for every path. index.php must NOT confirm
	// because it is indistinguishable from the per-extension soft-404 baseline.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>catch-all landing page</body></html>"))
	}))
	defer server.Close()

	engine, err := testEngineWithConfig(confirmTestConfig(server.URL, true))
	require.NoError(t, err)
	defer engine.Stop()
	engine.config.Extensions.Candidates = []string{"php"}

	u, err := url.Parse(server.URL)
	require.NoError(t, err)
	require.NoError(t, engine.learnBaselineFingerprints(u))
	engine.probeCandidateExtensions(startURLDirectory(u), 0)

	assert.False(t, engine.isExtensionConfirmed("php"),
		"php must NOT be confirmed on a catch-all host")
}

// TestConfirmExtension_CatchAllHostSuppressesObserved is the hooli.com regression:
// a modern SPA/CDN host 200s (and reflects) any path, so an observed .aspx URL
// (e.g. /overview/default.aspx on a Next.js site, or a seeded
// /Telerik.Web.UI.DialogHandler.aspx echoed by five unrelated hosts) must NOT
// confirm ASP.NET and queue a *.aspx wordlist fuzz. The catch-all guard probes a
// random <nonce>.aspx; it 200s here, so the confirmation is withheld.
func TestConfirmExtension_CatchAllHostSuppressesObserved(t *testing.T) {
	server := catchAllServer()
	defer server.Close()

	engine, err := testEngineWithConfig(confirmTestConfig(server.URL, false))
	require.NoError(t, err)
	defer engine.Stop()
	engine.config.Extensions.Candidates = []string{"aspx", "jsp", "php"}

	var events []ExtensionConfirmEvent
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) {
		events = append(events, ev)
	})

	// Observed source: a crawled/seeded .aspx URL on the catch-all host.
	assert.False(t, engine.confirmExtension("aspx", "observed", "/overview/default.aspx", 0),
		"aspx must NOT confirm on a catch-all host")
	assert.False(t, engine.isExtensionConfirmed("aspx"))

	// Fingerprint source is suppressed the same way.
	assert.False(t, engine.confirmExtension("jsp", "fingerprint", "Java/JSP via start URL", 0),
		"jsp must NOT confirm on a catch-all host")
	assert.False(t, engine.isExtensionConfirmed("jsp"))

	assert.Empty(t, events, "no wordlist fuzz should be queued on a catch-all host")
}

// TestConfirmExtension_GenuineHostConfirmsObserved proves the guard does not
// over-suppress: a real server-side host that 404s a random <nonce>.aspx still
// confirms .aspx from an observed URL.
func TestConfirmExtension_GenuineHostConfirmsObserved(t *testing.T) {
	server := notFoundServer()
	defer server.Close()

	engine, err := testEngineWithConfig(confirmTestConfig(server.URL, false))
	require.NoError(t, err)
	defer engine.Stop()
	engine.config.Extensions.Candidates = []string{"aspx", "php"}

	var confirmed []string
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) {
		confirmed = append(confirmed, ev.Extension)
	})

	assert.True(t, engine.confirmExtension("aspx", "observed", "/overview/default.aspx", 0),
		"aspx should confirm on a genuine host that 404s random files")
	assert.True(t, engine.isExtensionConfirmed("aspx"))
	assert.Contains(t, confirmed, "aspx")
}

// TestExtensionServedByCatchAll_CachesVerdict proves the catch-all verdict is
// probed once per extension and reused, so repeated observed URLs of the same
// extension on a catch-all host don't each re-probe the network.
func TestExtensionServedByCatchAll_CachesVerdict(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("shell"))
	}))
	defer server.Close()

	engine, err := testEngineWithConfig(confirmTestConfig(server.URL, false))
	require.NoError(t, err)
	defer engine.Stop()

	assert.True(t, engine.extensionServedByCatchAll("aspx"))
	first := atomic.LoadInt32(&hits)
	assert.Positive(t, first, "first call should probe the network")

	assert.True(t, engine.extensionServedByCatchAll("aspx"))
	assert.Equal(t, first, atomic.LoadInt32(&hits),
		"cached verdict must not re-probe for the same extension")
}

// allCandidateExts is the full server-side extension set the engine will fuzz —
// every extension across all fingerprint families (PHP, ASP.NET, Java/JSP,
// ColdFusion, CGI), matching config.DefaultCandidateExtensions. The guards must
// hold for each, so a regression on any single extension is caught here rather
// than in the field. Keep in sync with config.DefaultCandidateExtensions.
var allCandidateExts = []string{
	"php", "php3", "php4", "php5", "phtml",
	"asp", "aspx", "ashx", "asmx",
	"jsp", "jspx", "jspa", "do", "action",
	"cfm", "cfml",
	"cgi",
}

// TestAllCandidateExts_MatchesConfigDefault keeps the guard-coverage list in sync
// with the real default candidate set: if a new server-side extension is added to
// config.DefaultCandidateExtensions, this fails until allCandidateExts (and thus
// the per-extension guard tests above) covers it too — so a newly-fuzzed extension
// can never silently ship without the observed-seed + catch-all guards proven for it.
func TestAllCandidateExts_MatchesConfigDefault(t *testing.T) {
	assert.ElementsMatch(t, config.DefaultCandidateExtensions, allCandidateExts,
		"allCandidateExts must stay in sync with config.DefaultCandidateExtensions")
}

// TestConfirmExtension_CatchAllSuppressesEveryExtension proves the catch-all guard
// is extension-agnostic: on a host that 200s any path, NO candidate extension may
// confirm via either the observed or the fingerprint source. This is the
// generalization of the hooli.com .aspx/.jsp regression to every server-side stack.
func TestConfirmExtension_CatchAllSuppressesEveryExtension(t *testing.T) {
	server := catchAllServer()
	defer server.Close()

	for _, ext := range allCandidateExts {
		t.Run(ext, func(t *testing.T) {
			cfg := confirmTestConfig(server.URL, false)
			cfg.Extensions.Candidates = allCandidateExts
			engine, err := testEngineWithConfig(cfg)
			require.NoError(t, err)
			defer engine.Stop()

			assert.False(t, engine.confirmExtension(ext, "observed", "/x."+ext, 0),
				"%s must NOT confirm via observed on a catch-all host", ext)
			assert.False(t, engine.confirmExtension(ext, "fingerprint", "fp", 0),
				"%s must NOT confirm via fingerprint on a catch-all host", ext)
			assert.False(t, engine.isExtensionConfirmed(ext), "%s must not be marked confirmed", ext)
		})
	}
}

// TestConfirmStartURLExtensions_NonServedSeedSkipsEveryExtension proves the
// start-URL served-status gate is extension-agnostic: a redirect/404/5xx seed
// (a recon-fed probe path the host does not serve) confirms NO candidate
// extension, whatever its suffix.
func TestConfirmStartURLExtensions_NonServedSeedSkipsEveryExtension(t *testing.T) {
	server := notFoundServer()
	defer server.Close()

	for _, ext := range allCandidateExts {
		t.Run(ext, func(t *testing.T) {
			cfg := confirmTestConfig(server.URL+"/probe-seed."+ext, false)
			cfg.Extensions.Candidates = allCandidateExts
			cfg.Extensions.ConfirmViaFingerprint = false // isolate the observed source
			engine, err := testEngineWithConfig(cfg)
			require.NoError(t, err)
			defer engine.Stop()
			engine.startURLStatus = 302 // seed redirected away → not served

			engine.confirmStartURLExtensions()
			assert.False(t, engine.isExtensionConfirmed(ext),
				"%s must NOT confirm from a 302 seed", ext)
		})
	}
}

// TestConfirmStartURLExtensions_ServedSeedConfirmsEveryExtension proves the guards
// do not over-suppress ANY extension: a served (2xx) seed on a genuine host that
// 404s the random nonce confirms every candidate extension.
func TestConfirmStartURLExtensions_ServedSeedConfirmsEveryExtension(t *testing.T) {
	server := notFoundServer() // 404s the nonce probes → not a catch-all
	defer server.Close()

	for _, ext := range allCandidateExts {
		t.Run(ext, func(t *testing.T) {
			cfg := confirmTestConfig(server.URL+"/admin."+ext, false)
			cfg.Extensions.Candidates = allCandidateExts
			cfg.Extensions.ConfirmViaFingerprint = false
			engine, err := testEngineWithConfig(cfg)
			require.NoError(t, err)
			defer engine.Stop()
			engine.startURLStatus = 200 // seed served

			engine.confirmStartURLExtensions()
			assert.True(t, engine.isExtensionConfirmed(ext),
				"%s should confirm from a served seed on a genuine (nonce-404) host", ext)
		})
	}
}

// TestConfirmExtensionsFromHeaders_CatchAllSuppressesEveryFamily proves the whole
// fingerprint family→extension expansion (config.DetectTechExtensions) is guarded:
// each stack's session cookie must confirm NONE of its extensions on a catch-all
// host.
func TestConfirmExtensionsFromHeaders_CatchAllSuppressesEveryFamily(t *testing.T) {
	server := catchAllServer()
	defer server.Close()

	cases := []struct {
		name   string
		header http.Header
		exts   []string
	}{
		{"PHP", http.Header{"Set-Cookie": {"PHPSESSID=x; path=/"}}, []string{"php", "php3", "php4", "php5", "phtml"}},
		{"Java", http.Header{"Set-Cookie": {"JSESSIONID=x; Path=/"}}, []string{"jsp", "jspx", "jspa", "do", "action"}},
		{"ASP.NET", http.Header{"Set-Cookie": {"ASP.NET_SessionId=x; path=/"}}, []string{"aspx", "ashx", "asmx", "asp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := confirmTestConfig(server.URL, false)
			cfg.Extensions.Candidates = allCandidateExts
			engine, err := testEngineWithConfig(cfg)
			require.NoError(t, err)
			defer engine.Stop()

			engine.confirmExtensionsFromHeaders(tc.header.Get, tc.header.Values("Set-Cookie"), "start URL", 0)
			for _, ext := range tc.exts {
				assert.False(t, engine.isExtensionConfirmed(ext),
					"%s (%s) must NOT confirm on a catch-all host", ext, tc.name)
			}
		})
	}
}
