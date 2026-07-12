package csrf_verify

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const csrfSuccessBody = "<html><body>Item deleted successfully. Thank you.</body></html>"

// csrfFormReq builds a state-changing form POST that carries a session Cookie —
// the realistic shape the active verifier targets (CORS-simple body + ambient
// session). The CSRF preconditions (Cookie present, no Authorization, simple
// content type) all hold, so the module proceeds to probe the token.
func csrfFormReq(t *testing.T, rawURL, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	req := modtest.RequestMethod(t, "POST", rawURL, body).
		Request().
		WithAddedHeader("Cookie", "session=abc123def456")
	return httpmsg.NewHttpRequestResponse(req, nil)
}

// TestScanPerRequest_TokenIgnored fires when the server returns the SAME success
// page whether or not a valid CSRF token is present (token not validated).
func TestScanPerRequest_TokenIgnored(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(csrfSuccessBody)) // same outcome regardless of token
	}))
	defer srv.Close()

	rr := csrfFormReq(t, srv.URL+"/delete", "csrf_token=validtoken1234567890&id=42")
	rr = modtest.Response(rr, "text/html", csrfSuccessBody)

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a server that returns the same success page without a valid token must be flagged")
	assert.Contains(t, res[0].Info.Name, "CSRF Token Not Validated")
}

// TestScanPerRequest_JSONBeaconNotFlagged reproduces a real false positive: a
// Cloudflare RUM telemetry beacon (POST /cdn-cgi/rum, application/json body)
// carrying a "siteToken" field. siteToken is an application identifier, not an
// anti-CSRF token, and a JSON body is CORS non-simple (preflight-gated, not
// cross-origin-forgeable), so the request must not be flagged even though the
// server returns the same 204 regardless of the field. A Cookie is attached so
// the test isolates the content-type gate (not the no-cookie gate) as the cause.
func TestScanPerRequest_JSONBeaconNotFlagged(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent) // beacon accepts-and-discards regardless
	}))
	defer srv.Close()

	body := `{"siteToken":"bb500abe8ea54c71aec2a78c57f677cd","location":"https://a.biowarp.acme.com/","eventType":1}`
	req := modtest.RequestJSON(t, srv.URL+"/cdn-cgi/rum", body).
		Request().
		WithAddedHeader("Cookie", "session=abc123def456")
	rr := httpmsg.NewHttpRequestResponse(req, nil)

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a JSON telemetry beacon's siteToken must not be flagged as an unenforced CSRF token")
}

// TestScanPerRequest_BearerAuthNotFlagged ensures a header-authenticated request
// (Authorization: Bearer …) is not flagged: header auth is never replayed
// cross-site, so the endpoint is not CSRF-able regardless of token enforcement.
func TestScanPerRequest_BearerAuthNotFlagged(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(csrfSuccessBody))
	}))
	defer srv.Close()

	req := modtest.RequestMethod(t, "POST", srv.URL+"/delete", "csrf_token=validtoken1234567890&id=42").
		Request().
		WithAddedHeader("Cookie", "session=abc123def456").
		WithAddedHeader("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
	rr := httpmsg.NewHttpRequestResponse(req, nil)
	rr = modtest.Response(rr, "text/html", csrfSuccessBody)

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a Bearer-authenticated request is not CSRF-able and must not be flagged")
}

// TestScanPerRequest_NoCookieNotFlagged ensures a request with no Cookie header
// is not flagged: with no ambient session for an attacker to ride, an unenforced
// token is moot.
func TestScanPerRequest_NoCookieNotFlagged(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(csrfSuccessBody))
	}))
	defer srv.Close()

	rr := modtest.RequestMethod(t, "POST", srv.URL+"/delete", "csrf_token=validtoken1234567890&id=42")
	rr = modtest.Response(rr, "text/html", csrfSuccessBody)

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a cookieless request has no ambient session and must not be flagged")
}

// TestScanPerRequest_SoftReject200 ensures a server that returns a 200 but a
// DIFFERENT body (a CSRF-failure page) when the token is missing/invalid is NOT
// flagged — the body-equivalence gate distinguishes it from a real bypass.
func TestScanPerRequest_SoftReject200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Mutated requests get a clearly different CSRF-rejection page.
		_, _ = w.Write([]byte("<html><body>Security check failed: invalid CSRF token. " +
			"Your request was not processed. Please reload the form and try again.</body></html>"))
	}))
	defer srv.Close()

	rr := csrfFormReq(t, srv.URL+"/delete", "csrf_token=validtoken1234567890&id=42")
	rr = modtest.Response(rr, "text/html", csrfSuccessBody)

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 200 CSRF-failure page (different body) must not be flagged as a bypass")
}

// TestScanPerRequest_HardReject ensures a 4xx rejection of mutated tokens yields
// no finding.
func TestScanPerRequest_HardReject(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	rr := csrfFormReq(t, srv.URL+"/delete", "csrf_token=validtoken1234567890&id=42")
	rr = modtest.Response(rr, "text/html", csrfSuccessBody)

	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 403 on mutated tokens means CSRF is enforced")
}
