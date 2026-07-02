package input_reflection_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func makeHTTPCtx(rawReqLine, contentType, body string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("%s\r\nHost: example.com\r\n\r\n", rawReqLine))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n%s", contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

// TestScanPerRequest_Reflected drives a request whose query parameter value is
// echoed verbatim into the HTML response body and expects a reflection finding.
func TestScanPerRequest_Reflected(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /search?q=hello-world HTTP/1.1",
		"text/html",
		`<html><body>Results for hello-world</body></html>`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].ExtractedResults[0], "q=hello-world")
}

// TestScanPerRequest_NotReflected drives a request whose parameter value does
// NOT appear in the response body and expects no findings.
func TestScanPerRequest_NotReflected(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /search?q=hello-world HTTP/1.1",
		"text/html",
		`<html><body>No results found</body></html>`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NumericFilteredOut drives a request whose reflected value
// is all-numeric (filtered) and expects no findings.
func TestScanPerRequest_NumericFilteredOut(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /item?id=123456 HTTP/1.1",
		"text/html",
		`<html><body>Item 123456</body></html>`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_PathSegmentNotReflected is the regression for the dominant
// false positive across the Snapchat scan corpus: a route name reflecting in its
// own page. "/about" renders a page that naturally contains "about" (nav, title,
// canonical link), so treating the path segment as a reflected parameter is noise.
// Path segments must be skipped; only real query/body parameter values count.
func TestScanPerRequest_PathSegmentNotReflected(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /about HTTP/1.1",
		"text/html",
		`<html><head><link rel="canonical" href="/about"></head><body><nav>About us</nav></body></html>`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results, "a reflected path segment is a route name in its own page, not an injection signal")
}

// TestScanPerRequest_QueryReflectedDespitePathSegment ensures skipping path
// segments does not suppress a genuine query-parameter reflection sharing the
// same request.
func TestScanPerRequest_QueryReflectedDespitePathSegment(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /about?ref=hello-world HTTP/1.1",
		"text/html",
		`<html><body>About page for hello-world</body></html>`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].ExtractedResults[0], "ref=hello-world")
	for _, r := range results[0].ExtractedResults {
		assert.NotContains(t, r, "1=about", "positional path segment must not be reported")
	}
}

// TestScanPerRequest_NonHTML drives a JSON response (non-HTML) with a reflected
// value and expects the module to bail out before scanning.
func TestScanPerRequest_NonHTML(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx(
		"GET /search?q=hello-world HTTP/1.1",
		"application/json",
		`{"q":"hello-world"}`,
	)

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}
