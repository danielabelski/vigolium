package aspnet_sensitive_files

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestScanPerRequest_DetectsWebConfig serves an exposed ASP.NET web.config. The
// module fingerprints a random 404 then probes the sensitive-file paths and should
// flag /web.config (200 + <configuration>/<system.web> markers, no anti-markers).
func TestScanPerRequest_DetectsWebConfig(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/web.config" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<configuration><system.web><compilation debug=\"true\"/></system.web></configuration>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not-here unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a sensitive-file finding when /web.config is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures an HTML 404 (matching the
// defaultAntiMarkers) for every probe produces no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<!DOCTYPE html><html>404 Not Found</html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed sensitive files must not yield a finding")
}

// TestScanPerRequest_DetectsPermissiveCrossDomain serves a crossdomain.xml with a
// wildcard `domain="*"` allow rule. The confirmAny gate is satisfied, so the module
// flags it as Low severity with a title that does not falsely claim "ASP.NET".
func TestScanPerRequest_DetectsPermissiveCrossDomain(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crossdomain.xml" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not-here unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected a finding for a wildcard cross-domain policy")
	assert.Equal(t, severity.Low, res[0].Info.Severity, "wildcard cross-domain policy is Low severity")
	assert.NotContains(t, res[0].Info.Name, "ASP.NET", "cross-domain policy finding must not claim ASP.NET")
	assert.Contains(t, strings.Join(res[0].ExtractedResults, " "), `domain="*"`, "the permissive signal is surfaced")
}

// TestScanPerRequest_ScopedCrossDomainNoFinding reproduces the Netflix false positive:
// a crossdomain.xml scoped to a specific domain (`domain="*.example.com"`) is benign and
// must NOT be flagged, since the confirmAny wildcard signals never match a scoped policy.
func TestScanPerRequest_ScopedCrossDomainNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crossdomain.xml" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<cross-domain-policy>\n<allow-access-from domain=\"*.example.com\"/>\n</cross-domain-policy>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not-here unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a domain-scoped cross-domain policy must not yield a finding")
}

// TestScanPerRequest_DetectsClassicASPInclude serves an exposed classic ASP DB
// include carrying the full ADODB.Connection + password signature; only that path
// exists, so the same-extension decoy 404s and the finding stands.
func TestScanPerRequest_DetectsClassicASPInclude(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/includes/db.inc" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`Set conn = Server.CreateObject("ADODB.Connection")` + "\n" +
				`conn.Open "Provider=SQLOLEDB;Data Source=db;User Id=sa;password=S3cr3t;"`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not-here unique-baseline-marker"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding for an exposed classic ASP DB include")
}

// TestScanPerRequest_NoFP_ReflectedPasswordCatchAll reproduces the roche
// trace.rawaf-test echo server: every path returns 200 text/html reflecting the
// request (whose body carries "password"). The .inc probes require the full
// ADODB + Connection + password co-occurrence — which a request-echo page never
// carries — so a lone reflected "password" cannot forge a Critical finding.
func TestScanPerRequest_NoFP_ReflectedPasswordCatchAll(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Echo the requested path plus the reflected credential fields, but NONE of
		// the structural ADODB/Connection tokens a real include carries.
		_, _ = w.Write([]byte(`<span>` + r.URL.Path + ` username=admin password=1234 pwd=1234</span>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.RequestJSON(t, srv.URL+"/",
		`{"username":"admin","password":"1234"}`), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a request-echo catch-all must not be flagged as an exposed ASP include")
}

// TestScanPerRequest_NoFP_MarkerCatchAll covers a harder catch-all that serves a
// body carrying ALL of a probe's markers for EVERY path (so requireAll passes) —
// only the multi-round same-extension decoy disproof can catch it: a random
// /includes/vigolium-decoy-*.inc returns the same marker-bearing body, proving
// the host serves it for any path.
func TestScanPerRequest_NoFP_MarkerCatchAll(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`Set conn = Server.CreateObject("ADODB.Connection"); conn.Open "password=x"`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a marker-bearing catch-all must be disproved by the same-extension decoy")
}

// TestCanProcess_RequiresResponse verifies the module only runs with a baseline response.
func TestCanProcess_RequiresResponse(t *testing.T) {
	t.Parallel()
	m := New()
	bare := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(bare))
	assert.True(t, m.CanProcess(modtest.Response(bare, "text/html", "<html></html>")))
}
