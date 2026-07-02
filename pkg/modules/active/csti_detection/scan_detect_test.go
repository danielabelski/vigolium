package csti_detection

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerInsertionPoint_JSONEchoNotCSTI is the regression for the
// per-host-framework-cache false positive: the host serves an AngularJS SPA (so
// the framework fingerprint is cached as AngularJS), but the tested endpoint is a
// JSON API that echoes the {{...}} probe verbatim in its body. CSTI here is a
// pure literal reflection (not an evaluated product), so a JSON echo — which no
// template engine renders — must not be reported. The attack-response
// content-type gate must suppress it.
func TestScanPerInsertionPoint_JSONEchoNotCSTI(t *testing.T) {
	t.Parallel()
	// The probed endpoint is a JSON API that reflects the `q` parameter verbatim,
	// exactly like a FastAPI/Express validation error echoing the bad input.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"query":"` + r.URL.Query().Get("q") + `","ok":false}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// The captured baseline is the host's AngularJS SPA shell, so getFramework
	// fingerprints (and caches) this host as a framework — the precondition that
	// let the JSON endpoint inherit an HTML-rendering verdict.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/api/search?q=hello"),
		"text/html",
		`<html><body ng-app="myApp"><div id="app">Hello</div></body></html>`,
	)
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a {{...}} probe echoed inside a JSON body is never rendered by a template engine")
}

// TestScanPerInsertionPoint_HTMLReflectionStillDetected is the positive control:
// the same AngularJS host reflects the probe unescaped into an HTML response, the
// context where the framework actually evaluates {{...}}, so the finding must
// still fire.
func TestScanPerInsertionPoint_HTMLReflectionStillDetected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// AngularJS shell that reflects the query verbatim inside the app scope.
		_, _ = w.Write([]byte(`<html><body ng-app="myApp"><div id="app">` +
			r.URL.Query().Get("q") + `</div></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/page?q=hello"),
		"text/html",
		`<html><body ng-app="myApp"><div id="app">Hello</div></body></html>`,
	)
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "an unescaped {{...}} reflection in an HTML framework scope is a genuine CSTI")
}
