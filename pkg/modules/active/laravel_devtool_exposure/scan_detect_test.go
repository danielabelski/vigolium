package laravel_devtool_exposure

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

// TestScanPerRequest_DetectsClockwork drives the real scan method against a host
// exposing the Clockwork profiling endpoint at /__clockwork/latest. The module
// fingerprints a 404, then probes the dev-tool paths; the Clockwork markers must
// surface a finding.
func TestScanPerRequest_DetectsClockwork(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__clockwork/latest" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"clockwork":"5.x","controller":"HomeController",` +
				`"middleware":["web"],"databaseQueries":[{"query":"select * from users"}],` +
				`"timelineData":{}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a dev-tool finding when Clockwork profiling is exposed")
	assert.Contains(t, strings.ToLower(res[0].Info.Name), "laravel dev tool exposure")
}

// TestScanPerRequest_TruncatedTailCatchAllNoFalsePositive reproduces the
// universal catch-all / echo false positive: a host that returns HTTP 200 +
// text/html for LITERALLY ANY path, serving only a truncated TAIL fragment (no
// leading <!DOCTYPE/<html>) that reflects the request URI and carries a weak
// dev-tool name ("clockwork") as a CONSTANT word in the tail. The reflected-path
// strip cannot see a constant marker, and truncation defeats every
// body-similarity guard, so the multi-round decoy catch-all disproof (a random
// same-directory sibling serves the same marker) must drop every candidate.
// Without it the Clockwork probes forge findings.
func TestScanPerRequest_TruncatedTailCatchAllNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 for EVERY path (including the module's random 404 fingerprint probe
		// and the decoy siblings). Truncated tail: reflects the path, carries the
		// weak "clockwork" marker as a constant, no <!DOCTYPE/<html>.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`data-route="` + r.URL.Path + `"><script src="/js/clockwork-widget.js">`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a truncated-tail catch-all echo host must not yield a dev-tool finding")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host that 404s every probe must not yield a dev-tool finding")
}
