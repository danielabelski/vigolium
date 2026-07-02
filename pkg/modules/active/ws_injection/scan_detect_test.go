package ws_injection

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestNew_Metadata verifies module identity and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, ModuleTags, m.Tags())
}

// TestScanPerInsertionPoint_DetectsReflectedXSS drives the real scan method
// against a server that reflects a WS-named parameter unencoded into the body.
// The module only targets WebSocket-message-style parameter names (e.g.
// "message"), so the injected payload should surface as a finding.
func TestScanPerInsertionPoint_DetectsReflectedXSS(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the message parameter back verbatim (unencoded reflection) into an
		// HTML response — the context where injected markup actually renders.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<div>chat: " + r.URL.Query().Get("message") + "</div>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws?message=hello")
	ip := modtest.InsertionPoint(t, rr, "message")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an injection finding when a WS param reflects payloads")
	assert.True(t, res[0].MatcherStatus)
}

// TestScanPerInsertionPoint_JSONEchoNotXSS is the regression for the FastAPI
// JSON-validation-error false positive: a WS-named param is echoed verbatim
// (markup intact) inside an application/json body, so the raw-substring XSS match
// passes, yet the tag is a JSON string value that never renders as HTML. The
// content-type gate must drop the XSS category. (The SQLi/template categories are
// unaffected — their markers legitimately appear in JSON.)
func TestScanPerInsertionPoint_JSONEchoNotXSS(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// FastAPI/Pydantic-style validation error echoing the bad value.
		_, _ = w.Write([]byte(`{"detail":[{"loc":["query","message"],"input":"` +
			r.URL.Query().Get("message") + `"}]}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/ws?message=hello")
	ip := modtest.InsertionPoint(t, rr, "message")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an HTML payload echoed inside a JSON body is not rendered XSS")
}

// TestScanPerInsertionPoint_SkipsNonWSParam ensures a parameter whose name is
// not associated with WebSocket message processing is skipped entirely, even if
// it reflects.
func TestScanPerInsertionPoint_SkipsNonWSParam(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Query().Get("color")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws?color=red")
	ip := modtest.InsertionPoint(t, rr, "color")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "non-WebSocket parameter names must be skipped")
}

// TestScanPerInsertionPoint_NoFalsePositive ensures a WS-named parameter that is
// safely handled (no reflection, no SQL error, no command output) yields no
// finding.
func TestScanPerInsertionPoint_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("message received"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws?message=hello")
	ip := modtest.InsertionPoint(t, rr, "message")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a safely-handled WS param must not yield a finding")
}

// flagBody is a feature-flag JSON page (like a Salesforce SPA shell) that names
// DB engines and contains "49" — exactly the kind of static content whose bare
// substrings ("mysql", "49") tripped this module before the baseline/status
// gates. It reflects nothing.
const flagBody = `{"userHasMySqlEnabled":false,"userHasRedisEnabled":false,"build":49}`

// TestScanPerInsertionPoint_FeatureFlagBaselineNotFlagged covers the static-page
// FP: the page contains "mysql"/"49" in BOTH the captured baseline and the fuzzed
// response, so the baseline-absence gate must suppress it (the tokens are page
// content, not injection output).
func TestScanPerInsertionPoint_FeatureFlagBaselineNotFlagged(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(flagBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Capture a baseline that already carries the tokens.
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/ws?message=hello"),
		"application/json", flagBody,
	)
	ip := modtest.InsertionPoint(t, rr, "message")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "tokens present in the baseline are page content, not injection — must not be flagged")
}

// TestScanPerInsertionPoint_NotFoundShellNotFlagged covers the 404 catch-all FP:
// the fuzzed request resolves to a 404 shell whose body names DB engines. Even
// with no baseline, the status gate must drop a 404 before matching.
func TestScanPerInsertionPoint_NotFoundShellNotFlagged(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>Not Found " + flagBody + "</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws?message=hello")
	ip := modtest.InsertionPoint(t, rr, "message")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 404 shell naming DB engines must not be flagged as WS injection")
}
