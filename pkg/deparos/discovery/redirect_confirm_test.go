package discovery

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/queue"
	"github.com/vigolium/vigolium/pkg/deparos/discovery/testutil"
	dhttp "github.com/vigolium/vigolium/pkg/deparos/http"
)

// newRedirectConfirmHarness wires an engine + coordinator so handleRedirect drives
// the real OnFileDiscovered → extension-confirm path. The analyzer has a nil
// comparator, so it treats any non-404 (including our 302) as "found" — exactly how
// a per-path-distinct redirect Location slips past the wildcard soft-404 filter on
// a catch-all/SPA gateway in production.
func newRedirectConfirmHarness(t *testing.T) (*PayloadCoordinator, *Engine, *Callbacks) {
	t.Helper()
	engine, err := testEngineWithConfig(confirmTestConfig("http://example.test/", false))
	require.NoError(t, err)
	engine.config.Target.Recursion.Enabled = false // keep the focus on the confirm decision
	cb := &Callbacks{
		OnFileDiscovered: engine.OnFileDiscovered,
		Analyzer:         dhttp.NewAnalyzer(nil),
		RedirectDetector: NewRedirectDetector(),
		MaxDepth:         16,
	}
	return NewPayloadCoordinator(queue.New(), 2, cb), engine, cb
}

// driveRedirect feeds the coordinator a `status` response with Location=`location`
// for a request to `requestURL`, the way a worker would after a real probe.
func driveRedirect(t *testing.T, coord *PayloadCoordinator, cb *Callbacks, requestURL, location string, status int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	require.NoError(t, err)
	rc := testutil.NewMockRedirectResponse(status, location, "")
	coord.handleRedirect(context.Background(), req, requestURL, rc, 0, cb)
}

// TestHandleRedirect_PathPreservingDoesNotConfirm is the scim-bridge2.foundation.
// azure.initech.net regression: a SPA/gateway whose root 307'd and which bounced
// every fuzz-guessed path back to itself (a same-host, path-preserving 301/302)
// "confirmed" — and queued a full wordlist fuzz for — 7 mutually-exclusive
// server-side extensions at once, via the redirect branch's hardcoded
// foundByConfirmsExtension("redirect")=true. A self-bounce fires at the gateway
// before any handler runs, so it is no proof the server runs that stack: none may
// confirm. (Filenames are still harvested for discovery elsewhere.)
func TestHandleRedirect_PathPreservingDoesNotConfirm(t *testing.T) {
	coord, engine, cb := newRedirectConfirmHarness(t)
	defer engine.Stop()

	var confirmed []string
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) { confirmed = append(confirmed, ev.Extension) })

	// The exact fuzz-wordlist paths from the report (those whose extension is a
	// candidate); each 302-bounces to itself (Location == request URL).
	for _, tc := range []struct{ path, ext string }{
		{"/PDC/ajaxreq.php", "php"},
		{"/Telerik.Web.UI.DialogHandler.aspx", "aspx"},
		{"/authorization.do", "do"},
		{"/debug.cgi", "cgi"},
		{"/console/login/LoginForm.jsp", "jsp"},
		{"/crowd/console/login.action", "action"},
	} {
		u := "http://example.test" + tc.path
		driveRedirect(t, coord, cb, u, u, http.StatusFound)
		assert.False(t, engine.isExtensionConfirmed(tc.ext),
			"%s must NOT confirm from a path-preserving redirect (%s)", tc.ext, tc.path)
	}
	assert.Empty(t, confirmed, "no extension may confirm off a self-bouncing gateway")
}

// TestHandleRedirect_RelativeLocationPathPreserving covers the same self-bounce
// expressed as a relative Location header (common for cookie/auth round-trips):
// /x.php → Location: /x.php must still not confirm .php.
func TestHandleRedirect_RelativeLocationPathPreserving(t *testing.T) {
	coord, engine, cb := newRedirectConfirmHarness(t)
	defer engine.Stop()

	driveRedirect(t, coord, cb, "http://example.test/account/profile.php", "/account/profile.php", http.StatusMovedPermanently)
	assert.False(t, engine.isExtensionConfirmed("php"),
		"a relative-Location self-bounce must not confirm .php")
}

// TestHandleRedirect_DifferentPathConfirms guards against over-correction: when the
// server points a request at a genuinely different resource (a real server-emitted
// reference, not an echo of the request path), its extension still confirms — so
// the path-preserving gate must not suppress legitimate redirect-based discovery.
func TestHandleRedirect_DifferentPathConfirms(t *testing.T) {
	coord, engine, cb := newRedirectConfirmHarness(t)
	defer engine.Stop()

	var confirmed []string
	engine.SetExtensionConfirmCallback(func(ev ExtensionConfirmEvent) { confirmed = append(confirmed, ev.Extension) })

	driveRedirect(t, coord, cb, "http://example.test/portal", "http://example.test/app/home.php", http.StatusFound)

	assert.True(t, engine.isExtensionConfirmed("php"),
		"a redirect to a different served resource confirms its extension")
	assert.Contains(t, confirmed, "php")
}

// TestHandleRedirect_CrossStackCatchAllGuarded proves the two fixes compose end to
// end: even when a gateway redirects different paths to different *server-side
// stacks* (so the path-preserving gate does not apply), the one-stack-per-app guard
// still prevents confirming a second, incompatible stack — the broader catch-all
// the report's host is a special case of.
func TestHandleRedirect_CrossStackCatchAllGuarded(t *testing.T) {
	coord, engine, cb := newRedirectConfirmHarness(t)
	defer engine.Stop()

	driveRedirect(t, coord, cb, "http://example.test/a", "http://example.test/x.php", http.StatusFound)
	driveRedirect(t, coord, cb, "http://example.test/b", "http://example.test/y.jsp", http.StatusFound)

	assert.True(t, engine.isExtensionConfirmed("php"), "the first stack family confirms")
	assert.False(t, engine.isExtensionConfirmed("jsp"),
		"a second, incompatible stack must be refused by the catch-all guard")
}
