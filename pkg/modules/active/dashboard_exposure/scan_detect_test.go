package dashboard_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const spaShell = `<!doctype html><html><head><script>window.x=1</script></head>` +
	`<body><div id="root"></div><script src="/static/js/main.abc123.js"></script></body></html>`

// TestScanPerRequest_SkipsGenericSPA: a host that serves the same JS shell for
// every path (the random soft-404 included) and fingerprints no product must be
// skipped entirely — no probing, no findings.
func TestScanPerRequest_SkipsGenericSPA(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(spaShell))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a generic SPA host must be skipped")
}

// TestScanPerRequest_DashboardSPAStillDetected: a dashboard that IS an SPA
// (Grafana shell carries grafanaBootData, and /api/health leaks) must still be
// detected — the shell fingerprints the product, so it stays probeable.
func TestScanPerRequest_DashboardSPAStillDetected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"database":"ok","version":"10.2.0"}`))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head><script>window.grafanaBootData={user:{}}</script></head>` +
			`<body><div id="root"></div></body></html>`))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	found := false
	for _, r := range res {
		if r.Metadata["product"] == "grafana" {
			found = true
			assert.Equal(t, severity.High, r.Info.Severity)
		}
	}
	assert.True(t, found, "a Grafana SPA must still be detected via its /api/health leak")
}

// TestScanPerRequest_SSRNextJsNotSkipped: a server-rendered Next.js app carries
// __NEXT_DATA__ on every page (so the observed response "looks like" a framework
// app) but 404s unknown paths — it is NOT a blind SPA, so its real endpoints must
// still be probed. SPA-skip keys on the catch-all baseline (a 2xx shell on a
// random path), not on framework markers in the observed page.
func TestScanPerRequest_SSRNextJsNotSkipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"database":"ok","version":"10.3.0"}`))
			return
		}
		// SSR 404: a real Next.js 404 page returned with a 404 status.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<!doctype html><html><body><div id="__next"></div>` +
			`<script id="__NEXT_DATA__">{"page":"/404"}</script>Not Found</body></html>`))
	}))
	defer srv.Close()

	// The observed page is a server-rendered Next.js document (carries __NEXT_DATA__).
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html",
		`<!doctype html><html><body><div id="__next">homepage</div>`+
			`<script id="__NEXT_DATA__">{"props":{}}</script></body></html>`)

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	found := false
	for _, r := range res {
		if r.Metadata["product"] == "grafana" {
			found = true
		}
	}
	assert.True(t, found, "an SSR Next.js host that 404s unknown paths must still be probed, not SPA-skipped")
}

// TestScanPerRequest_SinglePatternReproduces: a single-signal confirmer (Chroma
// heartbeat) is reported when it reproduces on the second fetch.
func TestScanPerRequest_SinglePatternReproduces(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/heartbeat" {
			_, _ = w.Write([]byte(`{"nanosecond heartbeat":169123456789}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	found := false
	for _, r := range res {
		if r.Metadata["product"] == "chroma" {
			found = true
		}
	}
	assert.True(t, found, "a stable single-pattern endpoint should reproduce and report")
}

// TestScanPerRequest_FlakySinglePatternDropped: a single-signal confirmer that
// matches only on the first fetch (then changes) must NOT be reported — the
// reproduction requirement drops it.
func TestScanPerRequest_FlakySinglePatternDropped(t *testing.T) {
	t.Parallel()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/heartbeat" {
			if atomic.AddInt32(&n, 1) == 1 {
				_, _ = w.Write([]byte(`{"nanosecond heartbeat":1}`))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("transient error"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	for _, r := range res {
		assert.NotEqual(t, "chroma", r.Metadata["product"], "a non-reproducing single-pattern match must be dropped")
	}
}

// TestScanPerRequest_NoFP_HTMLReflectedVersion reproduces the acme
// trace.acme.com SonarQube false positive: an echo/catch-all host answers every
// path with 200 text/html, and the /api/server/version fragment happens to start
// with a version-shaped string (a reflected client IP left as "0.245.126.98" by a
// body-truncation quirk) that satisfies SonarQube's ^\s*\d+\.\d+ BodyRe. The
// content-type discipline for UnauthLeak confirmers must suppress it — a real
// version endpoint is never served as an HTML document.
func TestScanPerRequest_NoFP_HTMLReflectedVersion(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "version") {
			// Truncated tail that begins with a reflected-IP-shaped version.
			_, _ = w.Write([]byte("0.245.126.98\n<div>echo of " + r.URL.Path + "</div>"))
			return
		}
		_, _ = w.Write([]byte("<div>echo of " + r.URL.Path + "</div>"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	for _, r := range res {
		assert.NotEqual(t, "sonarqube", r.Metadata["product"],
			"an HTML echo page must not be flagged as an unauthenticated SonarQube version leak")
	}
}

// TestScanPerRequest_RealSonarQubeVersionStillDetected: a genuine SonarQube
// version endpoint returns the version as text/plain (not HTML), so the
// content-type gate lets it through and the leak is still reported.
func TestScanPerRequest_RealSonarQubeVersionStillDetected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/server/version" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("10.4.1.88267"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not-here"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	found := false
	for _, r := range res {
		if r.Metadata["product"] == "sonarqube" {
			found = true
			assert.Equal(t, severity.High, r.Info.Severity)
		}
	}
	assert.True(t, found, "a real text/plain SonarQube version leak must still be detected")
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
}

// TestScanPerRequest_GrafanaHealthLeak: an unauthenticated /api/health that leaks
// version + database status must be reported High.
func TestScanPerRequest_GrafanaHealthLeak(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"commit":"abc123","database":"ok","version":"10.1.0"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	var found *bool
	for _, r := range res {
		if r.Metadata["product"] == "grafana" {
			b := true
			found = &b
			assert.Equal(t, severity.High, r.Info.Severity, "unauth health leak must be High")
			assert.Contains(t, r.ExtractedResults, "version: 10.1.0")
			assert.True(t, r.Metadata["leak"].(bool))
		}
	}
	require.NotNil(t, found, "expected a Grafana leak finding")
}

// TestScanPerRequest_OllamaModelList: /api/tags leaking the installed model list.
func TestScanPerRequest_OllamaModelList(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3:latest","model":"llama3:latest","modified_at":"2024-01-01T00:00:00Z"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	found := false
	for _, r := range res {
		if r.Metadata["product"] == "ollama" {
			found = true
			assert.Equal(t, severity.High, r.Info.Severity)
		}
	}
	assert.True(t, found, "expected an Ollama model-list leak finding")
}

// TestScanPerRequest_NoFalsePositive: a host that 404s every probe yields nothing.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res)
}

// TestScanPerRequest_CatchAllGuard: a host that 200s EVERY path with the same
// JSON (including the random soft-404 probe) must not yield findings — the
// baseline catch-all guard drops every non-discriminating confirmer.
func TestScanPerRequest_CatchAllGuard(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"database":"ok","version":"9.9.9","status":"success"}`))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	for _, r := range res {
		t.Logf("unexpected finding: %s @ %s", r.Info.Name, r.URL)
	}
	assert.Empty(t, res, "a catch-all host must not produce dashboard findings")
}

// TestScanPerRequest_MarksTech verifies confirmed products are published to the
// TechRegistry (so downstream CVE/known-issue matching can use them).
func TestScanPerRequest_MarksTech(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/health") {
			_, _ = w.Write([]byte(`{"database":"ok","version":"10.0.0"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	sc := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	host := strings.TrimPrefix(srv.URL, "http://")
	_, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), sc)
	require.NoError(t, err)
	assert.True(t, sc.TechStack.Has(host, "grafana"))
	assert.True(t, sc.TechStack.Has(host, "dashboard"))
}
