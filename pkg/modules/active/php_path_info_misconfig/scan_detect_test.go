package php_path_info_misconfig

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsPathInfo simulates a cgi.fix_pathinfo=1 server where
// the injected PATH_INFO genuinely changes the output: a script WITH a trailing
// PATH_INFO segment is processed and reflects the injected path, while the bare
// base script (no PATH_INFO) and the random fingerprint path return a distinct
// 404. Because the PATH_INFO response diverges from the bare base script, the
// clean-canonical base-script control keeps the finding.
func TestScanPerRequest_DetectsPathInfo(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		low := strings.ToLower(r.URL.Path)
		idx := strings.Index(low, ".php")
		// PATH_INFO present == there is a segment after ".php".
		hasPathInfo := idx >= 0 && idx+len(".php") < len(low)
		isKnownScript := strings.Contains(low, "index.php") || strings.Contains(low, "script.php")
		if isKnownScript && hasPathInfo {
			// The injected path is processed and reflected — distinct from the
			// bare base script below.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>cgi.fix_pathinfo routed request, PATH_INFO=" +
				r.URL.Path + " processed by the PHP interpreter as a distinct application response</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("short 404"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when PATH_INFO requests return 200 app content distinct from the bare base script")
}

// TestScanPerRequest_NoFalsePositive_FrontControllerIgnoresPathInfo reproduces
// the static-root-traversal FP class for this module: a front controller (or
// Apache AcceptPathInfo) serves the SAME home page for /index.php and for
// /index.php/<anything>, so the trailing PATH_INFO has no observable effect. The
// random 404 fingerprint differs and the catch-all probe 404s, so only the
// clean-canonical base-script control (plain /index.php returns the same body)
// catches that nothing was actually routed.
func TestScanPerRequest_NoFalsePositive_FrontControllerIgnoresPathInfo(t *testing.T) {
	t.Parallel()
	const home = "<html><body>Welcome — single-page front controller home, served for /index.php and any trailing path alike</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /index.php and /index.php/<anything> both serve the identical home page;
		// non-existent scripts and unknown paths 404.
		if strings.Contains(strings.ToLower(r.URL.Path), "index.php") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(home))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("short 404"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a front controller serving the same page for /index.php and /index.php/<path> must not be flagged")
}

// TestScanPerRequest_NoFalsePositive ensures a server that rejects PATH_INFO
// requests with 404 yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server rejecting PATH_INFO must not yield findings")
}

// TestScanPerRequest_NoFalsePositive_CatchAll reproduces the off-by-slash-style
// false positive for PATH_INFO: the host serves one generic 200 shell for ANY
// path containing ".php" (a blanket rewrite / catch-all router) while returning
// a DISTINCT 404 for the random fingerprint path (which has no ".php"). The
// existing 404-fingerprint check passes (candidate differs from the 404), but
// the response does not actually depend on the script — every `*.php` URL is
// identical. The catch-all control gate must drop it.
func TestScanPerRequest_NoFalsePositive_CatchAll(t *testing.T) {
	t.Parallel()
	const shell = "<html><body>SPA application shell — served for every script-shaped path</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".php") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(shell))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>distinct not found page</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a blanket 200 for any *.php path (catch-all) must not be reported as PATH_INFO misconfig")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
