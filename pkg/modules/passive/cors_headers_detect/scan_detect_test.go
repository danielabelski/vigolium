package cors_headers_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeHTTPCtx builds a request/response pair where extraHeaders are appended to
// the response head (each "Name: Value" line, terminated by CRLF).
func makeHTTPCtx(path string, extraHeaders ...string) *httpmsg.HttpRequestResponse {
	return makeHTTPCtxOrigin(path, "", extraHeaders...)
}

// makeHTTPCtxOrigin is like makeHTTPCtx but lets a test set the request's Origin
// header (empty omits it) so reflection-correlated CORS logic can be exercised.
func makeHTTPCtxOrigin(path, origin string, extraHeaders ...string) *httpmsg.HttpRequestResponse {
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n", path)
	if origin != "" {
		rawReq += "Origin: " + origin + "\r\n"
	}
	rawReq += "\r\n"
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		[]byte(rawReq),
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	for _, h := range extraHeaders {
		rawResp += h + "\r\n"
	}
	rawResp += "\r\n<html></html>"
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_WildcardWithCredentials drives a wildcard ACAO combined
// with credentials, the most dangerous permissive CORS configuration.
func TestScanPerRequest_WildcardWithCredentials(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/data",
		"Access-Control-Allow-Origin: *",
		"Access-Control-Allow-Credentials: true",
	)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Description, "Wildcard")
}

// TestScanPerRequest_NullOrigin drives a null ACAO value which should be flagged.
func TestScanPerRequest_NullOrigin(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/data", "Access-Control-Allow-Origin: null")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// TestScanPerRequest_SameOriginCredentialsNotFlagged reproduces a real false
// positive: a server (here a Cloudflare RUM telemetry beacon shape) that reflects
// its OWN origin with Access-Control-Allow-Credentials: true. Echoing the site's
// own origin with credentials is the normal, safe pattern — only an ARBITRARY
// reflected origin is a CORS exposure — so it must not be flagged.
func TestScanPerRequest_SameOriginCredentialsNotFlagged(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/cdn-cgi/rum",
		"Access-Control-Allow-Origin: https://example.com", // the target's own origin
		"Access-Control-Allow-Credentials: true",
	)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "same-origin ACAO with credentials is safe and must not be flagged")
}

// TestScanPerRequest_SpecificOriginNoReflectionNotFlagged ensures a fixed
// allow-list origin (different host, but NOT echoed from the request Origin) with
// credentials is not flagged — without observed reflection it is a static
// allow-list entry, which is safe.
func TestScanPerRequest_SpecificOriginNoReflectionNotFlagged(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/api/data",
		"Access-Control-Allow-Origin: https://trusted-partner.com",
		"Access-Control-Allow-Credentials: true",
	)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a static allow-list origin with credentials (no observed reflection) must not be flagged")
}

// TestScanPerRequest_ReflectedCrossOriginCredentialsFlagged confirms the genuine
// vulnerability is still caught: the response echoes the request's CROSS-ORIGIN
// Origin header back together with credentials.
func TestScanPerRequest_ReflectedCrossOriginCredentialsFlagged(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtxOrigin("/api/data", "https://evil.attacker.com",
		"Access-Control-Allow-Origin: https://evil.attacker.com", // reflected attacker origin
		"Access-Control-Allow-Credentials: true",
	)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results, "a reflected cross-origin with credentials is a real CORS exposure")
	assert.Contains(t, results[0].Info.Description, "reflected cross-origin")
}

// TestScanPerRequest_NoCORS verifies a response without CORS headers is benign.
func TestScanPerRequest_NoCORS(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
