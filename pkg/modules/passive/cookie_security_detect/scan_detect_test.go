package cookie_security_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// makeHTTPCtx builds a request/response pair with the given path, content type,
// and Set-Cookie header value (omitted when empty).
func makeHTTPCtx(path, setCookie string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
	if setCookie != "" {
		rawResp += fmt.Sprintf("Set-Cookie: %s\r\n", setCookie)
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

// TestScanPerRequest_InsecureCookie drives a Set-Cookie missing all of the
// Secure, HttpOnly, and SameSite attributes on an HTTPS response, which is the
// main detection path.
func TestScanPerRequest_InsecureCookie(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/login", "sessionid=abc123; Path=/")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Info.Description, "sessionid")
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
}

func TestScanPerRequest_PreferenceCookieIsObservation(t *testing.T) {
	t.Parallel()
	results, err := New().ScanPerRequest(makeHTTPCtx("/", "theme=dark; Path=/"), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, output.RecordKindObservation, results[0].RecordKind)
}

func TestScanPerRequest_AttributeWordsInValueDoNotCountAsFlags(t *testing.T) {
	t.Parallel()
	results, err := New().ScanPerRequest(makeHTTPCtx("/login", "sessionid=secure-httponly-samesite; Path=/"), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	joined := results[0].Info.Description
	assert.Contains(t, joined, "Missing Secure")
	assert.Contains(t, joined, "Missing HttpOnly")
	assert.Contains(t, joined, "Missing SameSite")
}

// TestScanPerRequest_SecureCookie drives a fully-hardened cookie (Secure,
// HttpOnly, SameSite) which must produce no finding.
func TestScanPerRequest_SecureCookie(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/login", "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NoCookie verifies a response without any Set-Cookie header
// produces no finding.
func TestScanPerRequest_NoCookie(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/", "")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
