package openredirect_params

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// makeReqCtx builds a request-only context for the given request line.
func makeReqCtx(reqLine string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(reqLine + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	return httpmsg.NewHttpRequestResponse(req, nil)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

// TestScanPerRequest_RedirectParam drives a request whose query carries a
// redirect-like parameter, the open-redirect candidate trigger.
func TestScanPerRequest_RedirectParam(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("GET /login?next=1&redirect=https%3A%2F%2Fevil.com")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "redirect", results[0].FuzzingParameter)
}

// TestScanPerRequest_UrlParam drives the "url" parameter alias.
func TestScanPerRequest_UrlParam(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("GET /go?url=https%3A%2F%2Fx.com")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "url", results[0].FuzzingParameter)
}

// TestScanPerRequest_Benign verifies a request with no redirect-like params
// produces no finding.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeReqCtx("GET /search?q=hello&page=2")

	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_NonURLValueSkipped is the regression for the dominant
// false-positive class across the Snapchat scan corpus: a parameter whose *name*
// matches a redirect keyword but whose *value* can never be a redirect target.
// "location=Boulder" (a job-search city filter), "cb=<timestamp>" (a cache
// buster), and a long identifier whose name merely contains "url" must all be
// skipped.
func TestScanPerRequest_NonURLValueSkipped(t *testing.T) {
	t.Parallel()
	m := New()
	cases := []string{
		"GET /jobs?location=Boulder",
		"GET /jobs?location=San+Francisco",
		"GET /cm/s?bt=1d53c387&cb=1782847109189",
		"GET /s/sfsites/aura?getArticleUrlNameAndVersionId=1",
	}
	for _, reqLine := range cases {
		ctx := makeReqCtx(reqLine)
		results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
		require.NoError(t, err)
		assert.Empty(t, results, "non-URL redirect-keyword value must be skipped: %q", reqLine)
	}
}

// TestScanPerRequest_URLShapedValueFlagged verifies real redirect targets in
// every common shape still fire: absolute URL, protocol-relative, URL-encoded,
// internal path, and a scheme-less bare host.
func TestScanPerRequest_URLShapedValueFlagged(t *testing.T) {
	t.Parallel()
	m := New()
	cases := []string{
		"GET /login?redirect=//evil.com",
		"GET /login?redirect_uri=https%3A%2F%2Falt.example.io%2Fauth",
		"GET /go?url=/dashboard",
		"GET /go?callback=evil.com/steal",
	}
	for _, reqLine := range cases {
		ctx := makeReqCtx(reqLine)
		results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
		require.NoError(t, err)
		assert.NotEmpty(t, results, "URL-shaped redirect value must be flagged: %q", reqLine)
	}
}
