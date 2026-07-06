package xpath_injection

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
)

const xpathErr = "javax.xml.xpath.XPathExpressionException: unexpected token in expression"

// TestErrorBased_DetectsXPathError: an endpoint that leaks an XPath engine error
// when the value corrupts the expression (odd quote count) but not for benign
// input is reported.
func TestErrorBased_DetectsXPathError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if strings.Count(v, "'")%2 == 1 || strings.ContainsAny(v, `"]|`) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<html><body>" + xpathErr + "</body></html>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>user profile</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/lookup?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected an error-based XPath finding")
	assert.Equal(t, "XPath Injection", res[0].Info.Name)
}

// xpathBooleanTrue reports whether an injected value carries a tautology (an
// always-true comparison) as a genuine XPath engine would evaluate it — keyed on
// the boolean VALUE (1=1 / 7=7), not the `or` keyword, so the mock reacts to logic
// rather than a substring the way a real XML datastore does.
func xpathBooleanTrue(v string) bool {
	return strings.Contains(v, "1'='1") || strings.Contains(v, "7'='7") ||
		strings.Contains(v, "1=1") || strings.Contains(v, "7=7")
}

// xpathBooleanFalse reports whether an injected value carries a contradiction (an
// always-false comparison).
func xpathBooleanFalse(v string) bool {
	return strings.Contains(v, "1'='2") || strings.Contains(v, "3'='4") ||
		strings.Contains(v, "1=2") || strings.Contains(v, "3=4")
}

// TestBoolean_DetectsOracle: an XML-auth endpoint where an always-true predicate
// returns the record and an always-false predicate does not is reported via the
// boolean oracle. The mock evaluates the boolean VALUE (a tautology vs a
// contradiction), mirroring a real XPath engine — so an OR-keyword-but-false
// control (' or '1'='2) correctly renders the false page and does not suppress it.
func TestBoolean_DetectsOracle(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.WriteHeader(http.StatusOK)
		switch {
		case xpathBooleanTrue(v): // always-true injection
			_, _ = w.Write([]byte("<html><body>Welcome — all records: alice, bob, carol</body></html>"))
		case xpathBooleanFalse(v): // always-false injection
			_, _ = w.Write([]byte("<html><body>No matching record found</body></html>"))
		default: // baseline
			_, _ = w.Write([]byte("<html><body>record: " + v + "</body></html>"))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/lookup?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected a boolean-oracle XPath finding")
}

// TestNoFalsePositive_KeywordDifferential: a WAF/keyword endpoint that reacts to
// the `or` token rather than boolean truth (blocking every payload containing
// "or ", passing "and " ones) produces the same true/false shape as a real oracle,
// but the inert OR-keyword-but-false control also trips it — so it must NOT be
// flagged. This is the fcworkflow/acme.com `or 1=1` vs `and 1=2` false positive.
func TestNoFalsePositive_KeywordDifferential(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.WriteHeader(http.StatusOK)
		// Reacts to the OR keyword, not to the comparison's truth value.
		if strings.Contains(v, "or ") {
			_, _ = w.Write([]byte("<html><body>request blocked by security policy</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body>record: " + v + "</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/lookup?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a keyword/WAF differential must not be reported as XPath injection")
}

// TestNoFalsePositive_FlappingRedirect: a login/workflow endpoint that flaps
// between a 200 page and a 302 redirect independent of the input must not be read
// as a boolean oracle — the determinism/status gates reject it. This is the
// fcworkflow/acme.com non-deterministic redirect flow.
func TestNoFalsePositive_FlappingRedirect(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Alternate 200 and 302 per request, unrelated to the payload.
		if atomic.AddInt64(&n, 1)%2 == 0 {
			w.Header().Set("Location", "/workflow/logon.do")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>records: alice, bob, carol</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/workflow/lookup?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-deterministic 200/302-flapping endpoint must not be reported")
}

// TestNoFalsePositive_StaticShell: a SPA/static page that returns the same body
// for every input must not be flagged (no error, no true/false differential).
func TestNoFalsePositive_StaticShell(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><div id=app>loading…</div></body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a static SPA shell must not be reported as XPath injection")
}

// TestNoFalsePositive_StaticErrorPage: an endpoint that returns the XPath error
// string for EVERY input (including benign) is a static error page, not injection.
func TestNoFalsePositive_StaticErrorPage(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>" + xpathErr + " (service unavailable)</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/lookup?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a page that always shows the error must not be flagged")
}
