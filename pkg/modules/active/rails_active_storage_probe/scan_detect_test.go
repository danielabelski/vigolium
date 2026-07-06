package rails_active_storage_probe

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

// TestScanPerRequest_DetectsDirectUpload simulates a Rails app whose Active
// Storage direct-upload endpoint advertises POST via an Allow header on OPTIONS,
// with a distinct body from the random 404 path.
func TestScanPerRequest_DetectsDirectUpload(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions && r.URL.Path == "/rails/active_storage/direct_uploads" {
			// A genuine Rails route leaks a Ruby app-server fingerprint, which
			// the host-Rails gate requires before trusting the OPTIONS Allow header.
			w.Header().Set("Allow", "POST, OPTIONS")
			w.Header().Set("X-Runtime", "0.034219")
			w.Header().Set("Server", "Puma")
			w.WriteHeader(http.StatusNoContent)
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
	require.Len(t, res, 1, "expected exactly the direct-upload finding")
	require.NotEmpty(t, res[0].ExtractedResults)
	assert.Contains(t, strings.Join(res[0].ExtractedResults, " "), "Allow:",
		"evidence must cite the Allow header, not a body substring")
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence,
		"an OPTIONS-only Allow-header confirmation is heuristic and must be reported Tentative")
}

// TestScanPerRequest_GenericAllowBlankBodyNoFalsePositive reproduces the
// production false positive on vn.einvoice.initech.com: a generic front-controller
// answers OPTIONS on *every* path with a blank body and an over-broad
// "OPTIONS, TRACE, GET, HEAD, POST" Allow header (plus CORS headers). A real
// POST-only Active Storage / Action Mailbox route would never advertise
// GET/HEAD/TRACE, so the broad Allow set must be rejected. The root
// blanket-probe path 404s so the host-level guard cannot see it, isolating the
// per-response Allow-set gate.
func TestScanPerRequest_GenericAllowBlankBodyNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			// The root blanket-detector probe (a non-/rails path) 404s so the
			// host-level short-circuit does not fire and we exercise the Allow gate.
			if !strings.HasPrefix(r.URL.Path, "/rails/") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Allow", "OPTIONS, TRACE, GET, HEAD, POST")
			w.Header().Set("Access-Control-Allow-Origin", "https://vn.einvoice.initech.com")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK) // blank body
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("a distinct not found page body"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an over-broad GET/HEAD/TRACE Allow header on a blank-body OPTIONS must not be reported")
}

// TestScanPerRequest_NonRailsHostNoFalsePositive is the core production-FP
// guard: a host answers OPTIONS on the exact direct-upload path with a clean,
// POST-only "POST, OPTIONS" Allow and a blank body — passing the Allow-set gate
// — while random siblings 404 (passing the sibling baseline). But the host shows
// no Ruby/Rails fingerprint anywhere (no X-Runtime, no Ruby Server header, no
// Rails session cookie, no framework markers), so the OPTIONS Allow header is a
// generic proxy/middleware reply, not a mounted Rails route. The host-Rails gate
// drops it.
func TestScanPerRequest_NonRailsHostNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions && r.URL.Path == "/rails/active_storage/direct_uploads" {
			w.Header().Set("Allow", "POST, OPTIONS") // clean, POST-only — but no Rails fingerprint
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("a distinct not found page body"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an OPTIONS Allow header on a host with no Rails fingerprint must not be reported")
}

// TestScanPerRequest_SiblingCatchAllNoFalsePositive covers a catch-all OPTIONS
// handler mounted on the /rails prefix that answers a clean, POST-only
// "POST, OPTIONS" Allow on every path under it — including random siblings of
// the real route. The Allow set alone looks legitimate, so only the sibling
// baseline (same response with or without the real path) drops it. The root
// blanket-probe path 404s so the host-level guard cannot short-circuit first.
func TestScanPerRequest_SiblingCatchAllNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			if !strings.HasPrefix(r.URL.Path, "/rails/") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// Clean POST-only Allow on every /rails/* path, real or random.
			w.Header().Set("Allow", "POST, OPTIONS")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("a distinct not found page body"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a prefix-wide catch-all OPTIONS handler must not yield a Rails ingress finding")
}

// TestScanPerRequest_Nginx405NotAllowedNoFalsePositive reproduces the exact
// production false positive: nginx replies 405 to OPTIONS with the standard
// "405 Not Allowed" HTML page and NO Allow header. The old code (a) failed to
// reject status 405 and (b) body-matched the "Allow" marker against the
// substring inside "Not Allowed", forging a Mandrill ingress finding. The fix
// rejects 405 outright and confirms only on the Allow header.
func TestScanPerRequest_Nginx405NotAllowedNoFalsePositive(t *testing.T) {
	t.Parallel()
	const page = "<html>\n<head><title>405 Not Allowed</title></head>\n" +
		"<body>\n<center><h1>405 Not Allowed</h1></center>\n" +
		"<hr><center>nginx/1.23.0</center>\n</body>\n</html>\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(page))
			return
		}
		// Distinct GET 404 page so the fingerprint cannot reject the probe —
		// isolating the status/header gate as the only thing preventing a finding.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("a completely different not found page body"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an nginx 405 'Not Allowed' page must not yield a Rails ingress finding")
}

// TestScanPerRequest_200NotAllowedBodyNoFalsePositive guards the substring trap
// independently of status: even a 200 OPTIONS whose body says "Method Not
// Allowed" but carries no Allow header must not be reported. This proves the
// module no longer treats "Allow" (inside "Not Allowed") as a marker.
func TestScanPerRequest_200NotAllowedBodyNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Method Not Allowed for this resource"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope, different body"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 200 with no Allow header must not be reported, even if the body says 'Not Allowed'")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host without Active Storage endpoints must not yield findings")
}

// TestScanPerRequest_BlanketOptionsNoFalsePositive covers a reverse proxy / API
// gateway that answers OPTIONS with 200 + Allow:POST on *every* path. The
// host-level blanket detector short-circuits before any probe runs.
func TestScanPerRequest_BlanketOptionsNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST, OPTIONS")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a blanket-OPTIONS host must not yield findings")
}

// TestScanPerRequest_CORSPreflightNoFalsePositive covers an API gateway that
// answers OPTIONS for the ingress path with a generic CORS preflight (no Allow
// header). The blanket-probe path gets a 403 so the host-level guard cannot see
// it, isolating the per-response CORS-preflight guard.
func TestScanPerRequest_CORSPreflightNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			if strings.Contains(r.URL.Path, "vigolium-not-rails") {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"message":"Missing Authentication Token"}`))
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "OPTIONS,GET,PUT,POST,DELETE,PATCH,HEAD")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a generic CORS preflight must not be reported as an exposed Rails endpoint")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
