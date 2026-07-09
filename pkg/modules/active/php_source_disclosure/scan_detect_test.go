package php_source_disclosure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// phpSourceBody is raw PHP source served as plaintext (no surrounding HTML),
// matching the markers while avoiding the anti-markers.
const phpSourceBody = "<?php\n$config = array();\n$db = 'localhost';\necho 'hello';\n"

// TestScanPerRequest_DetectsSourceDisclosure serves raw PHP source at
// /index.php while returning a distinct 404 for the fingerprint path.
func TestScanPerRequest_DetectsSourceDisclosure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(phpSourceBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found page contents go here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when PHP source is served as plaintext")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// (and renders normal HTML for index.php) yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>Page Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that never leaks PHP source must not yield findings")
}

// TestScanPerRequest_TruncatedCatchAllNoFinding models the universal catch-all /
// echo server false positive: the host returns HTTP 200 + text/html for LITERALLY
// ANY path with a body that reflects the request URI (so the 404 fingerprint and
// modkit.ResemblesObservedPage never fire) and carries the weak source-disclosure
// markers in a TRUNCATED TAIL (no leading <!DOCTYPE/<html>/<head>/<body>, mimicking
// the gzip/Content-Length-0 quirk that strips the head so the anti-markers cannot
// match). Two guards keep this empty: the content-type=text/html rejection drops the
// plaintext-source probes (*.php/*.php5/*.inc — a real source leak is never an HTML
// document), and the multi-round decoy catch-all drops the .phps/.phtml highlighter
// probes (whose genuine hit IS HTML) because a random sibling returns the same tail.
func TestScanPerRequest_TruncatedCatchAllNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Tail carries <?php / <code> / <span style= / $ / password but deliberately
		// omits <html/<head>/<body>/<!DOCTYPE and the "404 Not Found"/"Page Not Found"
		// anti-markers (the truncated head is gone).
		_, _ = w.Write([]byte("catch-all shell reflecting " + r.URL.Path +
			` -- tail fragment leaking <?php $config = 'x'; password <code><span style="color">src</span></code> here`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "distinct home page body")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a universal catch-all echo server must not forge a source-disclosure finding")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
