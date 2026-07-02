package rails_info_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// railsInfoBody mimics the /rails/info page carrying the version markers.
const railsInfoBody = `<html><body>
<table>
<tr><td>Rails version</td><td>7.1.2</td></tr>
<tr><td>Ruby version</td><td>3.2.2</td></tr>
<tr><td>Application root</td><td>/app</td></tr>
</table>
</body></html>`

// TestScanPerRequest_DetectsRailsInfo serves the Rails info page at /rails/info
// with the version markers, while returning a distinct 404 elsewhere.
func TestScanPerRequest_DetectsRailsInfo(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rails/info" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(railsInfoBody))
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
	require.NotEmpty(t, res, "expected a finding when the Rails info page is exposed")
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
	assert.Empty(t, res, "a host without exposed Rails info endpoints must not yield findings")
}

// TestScanPerRequest_BlankUpBodyNoFalsePositive reproduces the catch-all FP
// where /up returns a blank 200 (Content-Length: 0) while unknown paths return a
// distinct non-empty 404. The blank body defeats the soft-404 fingerprint and
// wildcard guard (an empty body never matches the host's non-empty shell), so
// without the empty-body bail the markerless /up probe would wrongly fire.
func TestScanPerRequest_BlankUpBodyNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/up" {
			w.WriteHeader(http.StatusOK) // blank body, Content-Length: 0
			return
		}
		// Every other path (soft-404 fingerprint + wildcard probe + marker
		// probes) gets a distinct non-empty 404 so the blank /up body is not
		// suppressed by the fingerprint/length/ratio guards.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found body contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a blank-body 200 on /up must not be reported as a Rails health check")
}

// railsHealthBody is the exact page Rails::HealthController#show renders (Rails 7.1+).
const railsHealthBody = `<!DOCTYPE html><html><body style="background-color: #01d28e"></body></html>`

// TestScanPerRequest_GenuineUpHealthCheckReported serves the real Rails health page
// at /up (a text/html coloured-<body> banner) — it must be reported.
func TestScanPerRequest_GenuineUpHealthCheckReported(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/up" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(railsHealthBody))
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
	require.NotEmpty(t, res, "the genuine Rails health page at /up must be reported")
}

// TestScanPerRequest_NonRailsUpNoFalsePositive reproduces the observed mis-
// fingerprint: an Express/Node endpoint answers /up with a small 200 JSON geo
// payload ({"country":...}). It is not a Rails health check and must not fire.
func TestScanPerRequest_NonRailsUpNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/up" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("X-Powered-By", "Express")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"country":"ZZ","region":"na","regionSubdivision":"ZZNA"}`))
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
	assert.Empty(t, res, "a non-Rails JSON 200 on /up must not be reported as a Rails health check")
}

// TestLooksLikeRailsHealthCheck unit-covers the /up shape gate.
func TestLooksLikeRailsHealthCheck(t *testing.T) {
	t.Parallel()
	assert.True(t, looksLikeRailsHealthCheck("text/html; charset=utf-8", railsHealthBody))
	assert.True(t, looksLikeRailsHealthCheck("", railsHealthBody), "content-type may be absent")
	assert.False(t, looksLikeRailsHealthCheck("application/json", `{"country":"ZZ"}`), "JSON geo payload is not Rails")
	assert.False(t, looksLikeRailsHealthCheck("text/html", "<html><body>OK</body></html>"), "plain OK has no status banner")
	assert.False(t, looksLikeRailsHealthCheck("text/html", ""), "empty body is not a health page")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
