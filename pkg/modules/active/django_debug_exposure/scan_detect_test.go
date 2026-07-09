package django_debug_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsDebugPage drives the real scan method against a host
// running with DEBUG=True: its 404 handler renders the Django technical debug
// page exposing URL patterns and version info.
func TestScanPerRequest_DetectsDebugPage(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body><h1>Page not found (404)</h1>" +
			"<p>Request Method: GET</p><p>Request URL: http://x/foo</p>" +
			"<p>Using the URLconf defined in mysite.urls, Django tried these URL patterns</p>" +
			"<p>Django Version: 4.2.1</p></body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a Django debug finding when the technical 404 page is served")
}

// TestScanPerRequest_NoFalsePositive ensures a plain 404 (DEBUG=False) yields
// no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body><h1>Not Found</h1></body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-debug 404 page must not yield a finding")
}

// TestScanPerRequest_NoFalsePositive_SPAShell reproduces a catch-all/SPA host
// that returns the SAME 200 shell — embedding Django-looking strings — for every
// path including the random wildcard probe. The soft-404 gate must reject it.
func TestScanPerRequest_NoFalsePositive_SPAShell(t *testing.T) {
	t.Parallel()
	const shell = "<!doctype html><html><body><h1>Django App</h1>" +
		"<pre>Request Method: GET Request URL: / Django Version: 4.2</pre>" +
		"<div id=root></div></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK) // same 200 shell for every path & method
		_, _ = w.Write([]byte(shell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 200 catch-all shell echoing Django strings must not be reported")
}

// TestScanPerRequest_NoFalsePositive_TruncatedTailReflectingCatchAll reproduces the
// harder variant: a universal catch-all / echo host that returns 200 text/html for
// LITERALLY ANY path but REFLECTS the request path, so every response has a distinct
// head — defeating the soft-404 body fingerprint (which compares head bytes) — and
// the captured body is only a truncated tail fragment: no leading <!DOCTYPE/<html>,
// so the "404 Not Found" anti-marker is gone while a "Request Method:" /
// "Django Version:" token survives in the tail. A genuine Django technical debug
// page is a 4xx/5xx error surface, so the surviving 200 status must reject this.
func TestScanPerRequest_NoFalsePositive_TruncatedTailReflectingCatchAll(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK) // universal 200 for EVERY path & method
		// Reflected path first (distinct head per path), debug-shaped tokens in the tail.
		_, _ = w.Write([]byte(r.URL.Path + " <p>Request Method: " + r.Method +
			"</p><p>Request URL: " + r.URL.Path + "</p><p>Django Version: 4.2.1</p>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a reflecting 200 catch-all echoing Django debug tokens must not be reported")
}
