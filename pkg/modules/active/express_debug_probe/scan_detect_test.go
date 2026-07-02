package express_debug_probe

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsStackTrace drives the real scan method against an
// Express app running with verbose errors: the default handler dumps a Node.js
// stack trace including node_modules/ frames and an absolute file path. Echoing
// the request path keeps each probe body distinct from the 404 fingerprint.
func TestScanPerRequest_DetectsStackTrace(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Error: cannot handle " + r.URL.Path + "\n" +
			"    at Layer.handle (/usr/src/app/node_modules/express/lib/router/layer.js:95:5)\n" +
			"    at /usr/src/app/server.js:42:13\n"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/v1/items/42")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an Express debug finding when a Node.js stack trace leaks")
	// All probe techniques leak the same debug signal on this host; they must
	// collapse into a single finding (one http_record) rather than one per probe.
	require.Len(t, res, 1, "multiple debug probes must collapse into one finding per host")
	assert.NotEmpty(t, res[0].AdditionalEvidence, "the other probe techniques must be retained as inline evidence")
}

// TestAnalyzeErrorResponse_NodeModulesTokenTightened pins the tightened
// node_modules signal: a bare "node_modules/" mention or a static asset URL is no
// longer evidence (it appears in benign bundles / sourcemaps), while a real
// node_modules source-file path (as in a stack frame) still is.
func TestAnalyzeErrorResponse_NodeModulesTokenTightened(t *testing.T) {
	t.Parallel()

	assert.Empty(t, analyzeErrorResponse(`<script src="/node_modules/jquery/dist/jquery.min.js"></script>`),
		"a static node_modules asset URL must not count as a debug leak")
	assert.Empty(t, analyzeErrorResponse(`see the node_modules/ folder in the README`),
		"a bare node_modules/ mention must not count as a debug leak")

	ev := analyzeErrorResponse(`TypeError at node_modules/express/lib/router/layer.js:95:5`)
	assert.NotEmpty(t, ev, "a real node_modules source-file path in a stack frame must be flagged")
}

// TestScanPerRequest_NoFalsePositive ensures an app returning a clean,
// non-verbose error (no stack frames or paths) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"statusCode":404,"error":"Not Found","message":"Cannot GET"}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/v1/items/42")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a clean framework error shape must not yield a debug finding")
}
