package rails_admin_dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// sidekiqBody mimics the Sidekiq web UI landing page carrying the marker.
const sidekiqBody = `<!DOCTYPE html><html><head><title>Sidekiq</title></head>
<body><div class="dashboard">Sidekiq Web UI - Queues, Busy, Retries</div></body></html>`

// TestScanPerRequest_DetectsSidekiq serves the Sidekiq dashboard at /sidekiq
// with a 200 and the telltale marker, while returning a distinct 404 elsewhere.
func TestScanPerRequest_DetectsSidekiq(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sidekiq" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sidekiqBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found body contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the Sidekiq dashboard is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no findings.
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
	assert.Empty(t, res, "a host without exposed Rails dashboards must not yield findings")
}

// TestScanPerRequest_CatchAllReflectingNoFalsePositive reproduces the universal
// catch-all / echo-server false positive. The host answers EVERY path with a 200
// text/html fragment that (a) reflects the requested path — so /rails_admin and
// /active_admin echo their own "rails_admin"/"active_admin" marker — and (b)
// carries a constant "Sidekiq" word in a truncated TAIL (no <!DOCTYPE / <html>,
// so anti-markers are gone; the reflected path keeps each body distinct so the
// 404 fingerprint never matches). Without the reflected-path strip and the decoy
// catch-all confirmation, /sidekiq (constant marker) and /rails_admin (reflected
// marker) would both forge a dashboard finding.
func TestScanPerRequest_CatchAllReflectingNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Catch-all: 200 + text/html + reflected path + a constant brand word, for ANY path.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("you asked for " + r.URL.Path + " -- Sidekiq dashboard busy retries queue"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>Welcome to the Acme storefront landing page</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a reflecting HTML catch-all must not forge a Rails dashboard finding")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
