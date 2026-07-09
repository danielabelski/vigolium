package php_framework_debug

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// yiiDebugBody mimics the Yii debug module landing page carrying markers the
// module matches.
const yiiDebugBody = `<html><head><title>Yii Debugger</title></head>
<body><div class="yii-debug debug-panel">yii\debug request log</div></body></html>`

// TestScanPerRequest_DetectsYiiDebug serves the Yii debug module page at its
// probed path while returning a distinct 404 elsewhere.
func TestScanPerRequest_DetectsYiiDebug(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/default/index" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(yiiDebugBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found page contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the Yii debug module is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed framework debug endpoints must not yield findings")
}

// TestScanPerRequest_TruncatedCatchAllNoFinding models the universal catch-all /
// echo server false positive: the host returns HTTP 200 + text/html for LITERALLY
// ANY path with a body that reflects the request URI (so the 404 fingerprint and
// modkit.ResemblesObservedPage never fire) and carries a weak framework marker in a
// TRUNCATED TAIL (no leading <!DOCTYPE/<html>). Because the genuine hits here are
// themselves HTML (debug UIs, directory listings), the multi-round decoy catch-all is
// the guard: a random sibling under the probe's directory returns the same 200 +
// markers, disproving a real exposure. The tail deliberately omits the distinctive
// Slim markers, which a real catch-all would never emit.
func TestScanPerRequest_TruncatedCatchAllNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("catch-all shell reflecting " + r.URL.Path +
			` -- tail fragment leaking Yii Debugger yii\debug debug-panel and Index of Parent Directory .log here`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "distinct home page body")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a universal catch-all echo server must not forge a framework debug finding")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
