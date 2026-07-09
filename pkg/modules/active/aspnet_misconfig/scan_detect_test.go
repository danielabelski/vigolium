package aspnet_misconfig

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsTraceAxd serves an exposed ASP.NET trace handler at
// /trace.axd. The module fingerprints a random 404 then probes the diagnostic
// paths and should flag /trace.axd (200 + Application Trace markers).
func TestScanPerRequest_DetectsTraceAxd(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/trace.axd" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Application Trace<br>Request Details<br>Trace Information for app"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a misconfig finding when /trace.axd is exposed")
}

// TestScanPerRequest_DetectsYellowScreenOfDeath serves a verbose .NET error page
// for the aspxerrorpath probe so the YSoD detector fires.
func TestScanPerRequest_DetectsYellowScreenOfDeath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("aspxerrorpath") != "" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>Server Error in '/' Application. Stack Trace: Version Information: Microsoft .NET Framework 4.0</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found - unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a YSoD finding when a verbose .NET error page is returned")
}

// TestScanPerRequest_CatchAllEchoNoFalsePositive reproduces the universal
// catch-all / echo-server FP: the host answers LITERALLY ANY path with 200 +
// text/html and the SAME reflecting page whose body is only a truncated tail (no
// <!DOCTYPE/<html> — the gzip + Content-Length:0 quirk) that happens to carry
// weak diagnostic-dashboard words ("Dashboard", "profiler", "Glimpse",
// "connectionId") plus the reflected request path. The 404 fingerprint cannot see
// it (the reflected path makes every response distinct) and the observed-page
// guard cannot (the tail differs from the home page). The content-type discipline
// (SignalR JSON/JS) and the multi-round decoy catch-all (HTML dashboards) must
// together yield NO finding.
func TestScanPerRequest_CatchAllEchoNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(
			`<nav class="Dashboard">Glimpse glimpseData MiniProfiler profiler Hangfire hangfire ` +
				`connectionId negotiateVersion signalR hubConnection</nav>` +
				`<span>route: ` + r.URL.Path + `</span>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a universal catch-all/echo host must not forge a diagnostics finding")
}

// TestScanPerRequest_YSoDCatchAllNoFalsePositive ensures a catch-all/echo host
// whose truncated tail merely contains the weak "Stack Trace:" string (but not the
// "Server Error in" YSoD page anchor) does not forge a Yellow-Screen-of-Death
// finding — the AND-of-OR co-occurrence guard is what rejects it.
func TestScanPerRequest_YSoDCatchAllNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Tail mentions "Stack Trace:" (a JS console helper) but is NOT a .NET YSoD.
		_, _ = w.Write([]byte(`<div>console.Stack Trace: helper</div><span>route: ` + r.URL.Path + `</span>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all tail with only a weak 'Stack Trace:' word must not forge a YSoD finding")
}

// TestScanPerRequest_NoFalsePositive ensures a host with no diagnostic endpoints
// (all probes 404) produces no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 Not Found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed diagnostics must not yield a finding")
}

// TestCanProcess_RequiresResponse verifies the module only runs with a baseline response.
func TestCanProcess_RequiresResponse(t *testing.T) {
	t.Parallel()
	m := New()
	bare := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(bare))
	assert.True(t, m.CanProcess(modtest.Response(bare, "text/html", "<html></html>")))
}
