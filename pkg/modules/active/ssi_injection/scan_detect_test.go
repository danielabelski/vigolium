package ssi_injection

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

var ssiDirective = regexp.MustCompile(`<!--#set var="vgnssi" value="([^"]*)"--><!--#echo var="vgnssi"-->`)

// ssiProcessingServer emulates an SSI-enabled document: it evaluates the set/echo
// directive, emitting only its value and consuming the directive markup.
func ssiProcessingServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		out := ssiDirective.ReplaceAllString(q, "$1")
		_, _ = w.Write([]byte("<html><body>result: " + out + "</body></html>"))
	}))
}

// TestScanPerInsertionPoint_DetectsSSI: the server evaluates the directive, so the
// canary is emitted without the directive markup — a confirmed SSI injection.
func TestScanPerInsertionPoint_DetectsSSI(t *testing.T) {
	t.Parallel()
	srv := ssiProcessingServer()
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/page.shtml?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "an SSI-evaluating endpoint must be reported")
	assert.Equal(t, ModuleName, res[0].Info.Name)
	assert.Equal(t, "q", res[0].FuzzingParameter)
}

// TestScanPerInsertionPoint_ReflectionNotSSI: the server reflects the payload
// verbatim (directive tokens survive), so it must not be reported — the key SSI
// false positive.
func TestScanPerInsertionPoint_ReflectionNotSSI(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verbatim reflection: the "#set"/"#echo" tokens remain in the output.
		_, _ = w.Write([]byte("<html><body>result: " + r.URL.Query().Get("q") + "</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/page?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "verbatim reflection of the directive must not be reported as SSI")
}

// TestSSIEvaluated exercises the pure differential predicate.
func TestSSIEvaluated(t *testing.T) {
	t.Parallel()
	assert.True(t, ssiEvaluated("result: abc123", "abc123"), "value emitted, no directive tokens -> SSI")
	assert.False(t, ssiEvaluated(`result: <!--#echo var="vgnssi"-->`, "abc123"), "directive token present -> reflection")
	assert.False(t, ssiEvaluated("result: nothing here", "abc123"), "value absent -> no signal")
}
