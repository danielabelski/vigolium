package xpath_injection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
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

// xpathCondRe extracts a trailing  ' <op> '<a>'='<b>  clause from an injected XPath
// string-context value (e.g. admin' or '1'='1).
var xpathCondRe = regexp.MustCompile(`'\s*(or|and)\s*'([^']*)'='([^']*)$`)

// xpathTrueFns / xpathFalseFns are the exact XPath-core-function sub-expressions the
// module's engine discriminator injects, split by their (constant) boolean value. A
// faithful XPath engine evaluates the true set to true and the false set to false; the
// operand sets are chosen so no true sub-expression is a substring of a false one, so a
// simple Contains match reproduces real XPath semantics for the mock.
var (
	xpathTrueFns = []string{
		`string-length('vig')>0`, `string-length('xyzzy1')>2`,
		`local-name(.)=local-name(.)`, `count(.)>=0`,
		`normalize-space('x')='x'`, `boolean(1)`,
	}
	xpathFalseFns = []string{`string-length('vig')>999`, `count(.)>999`}
)

// xpathRender simulates //user[name='<v>'] over a fixed dataset and returns the page
// a real XPath engine yields: the always-true page (predicate forced true → all
// records), the always-false page (forced false → none), or the baseline (the query
// still keys on name → the single matched record). It is faithful to boolean
// semantics — an OR-false or AND-true clause is INERT and collapses to the name
// lookup (baseline) — so the module's symmetric inert controls behave as they would
// against a real target, rather than being mis-keyed on a substring.
func xpathRender(v string) string {
	const (
		allPage  = "<html><body>directory listing: admin alice bob carol dave erin frank grace heidi</body></html>"
		nonePage = "<html><body>no matching record found for that query</body></html>"
		basePage = "<html><body>profile card for the single matched account</body></html>"
	)
	// A genuine XPath engine evaluates core-function tautologies as TRUE and
	// contradictions as FALSE regardless of the trailing comparison, so an
	// `... or <true-fn> or ...` predicate forces the full record set and an
	// `... and <false-fn> and ...` predicate forces none. These functions have no SQL
	// equivalent, which is exactly how the module's engine discriminator tells an XPath
	// sink apart from a SQL boolean oracle sharing ' or '1'='1. The true/false operand
	// sets are disjoint substrings so matching is unambiguous.
	for _, trueFn := range xpathTrueFns {
		if strings.Contains(v, trueFn) {
			return allPage
		}
	}
	for _, falseFn := range xpathFalseFns {
		if strings.Contains(v, falseFn) {
			return nonePage
		}
	}
	m := xpathCondRe.FindStringSubmatch(v)
	if m == nil {
		return basePage // no injected clause → plain name lookup
	}
	op, a, b := m[1], m[2], m[3]
	cmp := a == b
	switch {
	case op == "or" && cmp:
		return allPage // name=... OR true → always true → all records
	case op == "and" && !cmp:
		return nonePage // name=... AND false → always false → none
	default:
		return basePage // OR-false / AND-true → inert → collapses to the name lookup
	}
}

// TestBoolean_DetectsOracle: an XML-lookup endpoint that evaluates real XPath boolean
// logic (three always-true operands all expand to the full record set, three
// always-false operands all return none, and inert OR-false/AND-true controls
// collapse to the baseline) is reported via the boolean oracle.
func TestBoolean_DetectsOracle(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(xpathRender(r.URL.Query().Get("id"))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// An XML content-type gives the boolean leg its required XPath-context evidence —
	// a realistic XML web service backing the lookup.
	rr := modtest.Response(modtest.Request(t, srv.URL+"/lookup?id=admin"), "application/xml", `<?xml version="1.0"?><users/>`)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "expected a boolean-oracle XPath finding")
}

// TestNoFalsePositive_XPathOracleWithoutContext: the SAME endpoint as
// TestBoolean_DetectsOracle — one that evaluates real XPath boolean logic — but served
// as text/html from a non-XML path with a generic parameter, i.e. with NO XML/XPath
// context evidence. The tech-stack gate must skip the boolean leg entirely, so even a
// genuine-looking oracle is not reported without positive XML evidence. This is the core
// FP-reduction guarantee: a boolean differential on an ordinary web page (where SQL is
// far more likely than XPath) is never labelled XPath.
func TestNoFalsePositive_XPathOracleWithoutContext(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(xpathRender(r.URL.Query().Get("id"))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/lookup?id=admin"), "text/html; charset=utf-8", "<html></html>")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a boolean oracle without XML/XPath context must not be reported (tech-stack gate)")
}

// sqlBoolLookup renders WHERE category='<v>' with boolean semantics IDENTICAL to a
// real XPath name lookup for the shared ' or '1'='1 / ' and '1'='2 payloads (OR-true→all
// rows, AND-false→none, inert OR-false/AND-true→baseline). The one difference — and the
// only thing that tells the two engines apart — is that an XPath CORE FUNCTION is a SQL
// syntax error: string-length()/local-name() never reach the all-rows page. This models
// the ginandjuice.shop `category` SQL injection, whose boolean oracle is byte-for-byte
// what the XPath boolean leg looks for.
func sqlBoolLookup(v string) string {
	const (
		allPage  = "<html><body>directory listing: admin alice bob carol dave erin frank grace heidi</body></html>"
		nonePage = "<html><body>no matching record found for that query</body></html>"
		basePage = "<html><body>profile card for the single matched account</body></html>"
		errPage  = "<html><body>500 Internal Server Error: SQL syntax error near unexpected token</body></html>"
	)
	// A SQL engine cannot parse XPath functions — the whole statement errors out.
	if strings.Contains(v, "string-length(") || strings.Contains(v, "local-name(") ||
		strings.Contains(v, "count(") || strings.Contains(v, "normalize-space(") ||
		strings.Contains(v, "boolean(") {
		return errPage
	}
	m := xpathCondRe.FindStringSubmatch(v)
	if m == nil {
		return basePage
	}
	op, a, b := m[1], m[2], m[3]
	cmp := a == b
	switch {
	case op == "or" && cmp:
		return allPage
	case op == "and" && !cmp:
		return nonePage
	default:
		return basePage
	}
}

// TestNoFalsePositive_SQLBooleanOracle: the reported real-world false positive — a
// SQL-injectable parameter (the classic ginandjuice.shop `category`) on a plain text/html
// page. Its ' or '1'='1 / ' and '1'='2 boolean oracle is identical to XPath's, but the
// endpoint shows NO XML/XPath context (HTML content-type, non-XML path, generic param),
// so the tech-stack gate skips the boolean leg outright — the boolean oracle is never
// even probed. Must NOT be flagged as XPath.
func TestNoFalsePositive_SQLBooleanOracle(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sqlBoolLookup(r.URL.Query().Get("category"))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/catalog?category=Gin"), "text/html; charset=utf-8", "<html></html>")
	ip := modtest.InsertionPoint(t, rr, "category")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a SQL boolean oracle on a non-XML endpoint (ginandjuice.shop category) must not be reported as XPath injection")
}

// TestNoFalsePositive_SQLBackedXMLService: defense in depth for when the tech-stack gate
// DOES pass — an XML/SOAP web service whose parameter is actually SQL-injectable. The
// endpoint has XML context (application/xml), so the boolean leg runs and every generic
// check passes just as it would for XPath; only the multi-round XPath-core-function
// discriminator separates them, because string-length()/local-name()/count()/… are SQL
// syntax errors that reproduce neither the true nor the false page. Must NOT be flagged.
func TestNoFalsePositive_SQLBackedXMLService(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sqlBoolLookup(r.URL.Query().Get("category"))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/services/catalog?category=Gin"), "application/xml", `<?xml version="1.0"?><catalog/>`)
	ip := modtest.InsertionPoint(t, rr, "category")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a SQL-backed XML service must not be reported as XPath injection")
}

// TestNoFalsePositive_LiteralKeyedDifferential: an endpoint that keys on the literal
// comparison (a tautology 'N'='N vs a contradiction 'N'='M) but IGNORES the
// surrounding operator renders the "many" page for an AND-true payload too. The old
// single OR-false control missed this (OR-false renders "few"); the symmetric AND-true
// control catches it — the differential tracks the literal, not boolean truth.
func TestNoFalsePositive_LiteralKeyedDifferential(t *testing.T) {
	t.Parallel()
	// RE2 has no backreferences, so capture both operands and compare them in Go.
	cmpRe := regexp.MustCompile(`'(\d)'='(\d)`) // 'N'='M
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.WriteHeader(http.StatusOK)
		m := cmpRe.FindStringSubmatch(v)
		switch {
		case m != nil && m[1] == m[2]: // tautology 'N'='N — keyed on the literal, not the operator
			_, _ = w.Write([]byte("<html><body>MANY results: a b c d e f g h i j</body></html>"))
		case m != nil: // contradiction 'N'='M
			_, _ = w.Write([]byte("<html><body>FEW: no rows</body></html>"))
		default:
			_, _ = w.Write([]byte("<html><body>BASE: profile</body></html>"))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/lookup?id=admin"), "application/xml", `<?xml version="1.0"?><r/>`)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a literal-keyed (operator-ignoring) differential must not be reported")
}

// TestNoFalsePositive_InconsistentAcrossOperands: an endpoint whose result set tracks
// the operand VALUE rather than boolean truth (operands 1/7 return one set, operand 9
// another) must not be flagged. A real XPath tautology makes the operand irrelevant,
// so three independent always-true operands must agree; here the third disagrees. The
// old two-operand matrix would have passed on operands 1 and 7 alone.
func TestNoFalsePositive_InconsistentAcrossOperands(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.WriteHeader(http.StatusOK)
		switch {
		case strings.Contains(v, "1'='1") || strings.Contains(v, "7'='7"):
			_, _ = w.Write([]byte("<html><body>result set alpha: rows 1 through 10 listed here</body></html>"))
		case strings.Contains(v, "9'='9"):
			_, _ = w.Write([]byte("<html><body>totally different beta payload: xyzzy plugh</body></html>"))
		default:
			_, _ = w.Write([]byte("<html><body>empty or baseline view</body></html>"))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/lookup?id=admin"), "application/xml", `<?xml version="1.0"?><r/>`)
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a value-tracking differential that disagrees across operands must not be reported")
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
	rr := modtest.Response(modtest.Request(t, srv.URL+"/lookup?id=admin"), "application/xml", `<?xml version="1.0"?><r/>`)
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
	rr := modtest.Response(modtest.Request(t, srv.URL+"/workflow/lookup?id=admin"), "application/xml", `<?xml version="1.0"?><r/>`)
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
	rr := modtest.Response(modtest.Request(t, srv.URL+"/app?id=admin"), "application/xml", `<?xml version="1.0"?><r/>`)
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

// requestWithHeader builds a GET request that carries one extra header, so a header
// insertion point (INS_HEADER) named after it can be exercised.
func requestWithHeader(t *testing.T, rawURL, name, value string) *httpmsg.HttpRequestResponse {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	port := 80
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		require.NoError(t, err)
	} else if u.Scheme == "https" {
		port = 443
	}
	svc, err := httpmsg.NewService(u.Hostname(), port, u.Scheme)
	require.NoError(t, err)
	target := u.RequestURI()
	if target == "" {
		target = "/"
	}
	raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\n\r\n", target, u.Host, name, value)
	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))
	return httpmsg.NewHttpRequestResponse(req, nil)
}

// TestNoFalsePositive_StandardRequestHeader: a boolean-oracle-shaped endpoint keyed
// on the Accept-Language header must NOT be flagged — a fixed browser header is never
// an XPath sink. This is the evr-kr.roche.com /cdn-cgi Accept-Language false positive
// (the header gate rejects it even before the CDN-path gate would).
func TestNoFalsePositive_StandardRequestHeader(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("Accept-Language")
		w.WriteHeader(http.StatusOK)
		switch {
		case xpathBooleanTrue(v):
			_, _ = w.Write([]byte("<html><body>all records: alice, bob, carol</body></html>"))
		case xpathBooleanFalse(v):
			_, _ = w.Write([]byte("<html><body>No matching record found</body></html>"))
		default:
			_, _ = w.Write([]byte("<html><body>record: home</body></html>"))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := requestWithHeader(t, srv.URL+"/lookup", "Accept-Language", "en-US")
	ip := modtest.InsertionPoint(t, rr, "Accept-Language")
	require.Equal(t, httpmsg.INS_HEADER, ip.Type(), "expected a header insertion point")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "XPath must not be tested on a standard browser request header")
}

// highEntropyBlob returns 2048 bytes cycling all 256 values XOR seed (entropy ≈ 8),
// modeling a per-request encrypted CDN/challenge body. Distinct seeds yield distinct,
// dissimilar blobs so the mock forms a boolean-oracle-shaped differential that would
// otherwise fire.
func highEntropyBlob(seed byte) []byte {
	b := make([]byte, 2048)
	for i := range b {
		b[i] = byte(i) ^ seed
	}
	return b
}

// TestNoFalsePositive_OpaqueBody: an endpoint whose responses are opaque, per-request
// high-entropy blobs (encrypted CDN challenge content) must NOT be flagged even when
// the true/false blobs differ — an opaque body is no XPath surface, and its content
// churn is what fools the boolean oracle. Uses a query param so the opaque-body gate,
// not the header gate, is what rejects it.
func TestNoFalsePositive_OpaqueBody(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.WriteHeader(http.StatusOK)
		switch {
		case xpathBooleanTrue(v):
			_, _ = w.Write(highEntropyBlob(0x11))
		case xpathBooleanFalse(v):
			_, _ = w.Write(highEntropyBlob(0x22))
		default:
			_, _ = w.Write(highEntropyBlob(0x33))
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/lookup?id=admin")
	ip := modtest.InsertionPoint(t, rr, "id")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an opaque high-entropy body must not be reported as XPath injection")
}
