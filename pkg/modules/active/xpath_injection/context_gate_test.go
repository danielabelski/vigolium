package xpath_injection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestIsXMLMediaType(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		"application/xml":                   true,
		"text/xml":                          true,
		"application/xml; charset=utf-8":    true,
		"application/soap+xml":              true,
		"application/rss+xml":               true,
		"application/atom+xml":              true,
		"text/html":                         false,
		"text/html; charset=utf-8":          false,
		"application/json":                  false,
		"application/xhtml+xml":             false, // XHTML is HTML delivered as XML — not an XPath sink
		"":                                  false,
		"application/x-www-form-urlencoded": false,
	}
	for ct, want := range tests {
		assert.Equalf(t, want, isXMLMediaType(ct), "isXMLMediaType(%q)", ct)
	}
}

func TestLooksLikeXMLBody(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		`<?xml version="1.0"?><users/>`:                                true,
		"  \n<?xml version=\"1.0\" encoding=\"UTF-8\"?><a/>":           true,
		`<soap:Envelope xmlns:soap="..."><soap:Body/></soap:Envelope>`: true,
		`<soapenv:Envelope><soapenv:Body/></soapenv:Envelope>`:         true,
		`<!DOCTYPE html><html><body>x</body></html>`:                   false,
		`<html><head></head><body></body></html>`:                      false,
		`<div class="card">profile</div>`:                              false, // bare HTML fragment
		`{"users":["a","b"]}`:                                          false,
		``:                                                             false,
		`   `:                                                          false,
	}
	for body, want := range tests {
		assert.Equalf(t, want, looksLikeXMLBody(body), "looksLikeXMLBody(%q)", body)
	}
}

// TestHasXPathContextEvidence exercises every positive signal and the negative case.
func TestHasXPathContextEvidence(t *testing.T) {
	t.Parallel()

	t.Run("response xml content-type", func(t *testing.T) {
		rr := modtest.Response(modtest.Request(t, "http://x.test/catalog?category=Gin"), "application/xml", "<c/>")
		ip := modtest.InsertionPoint(t, rr, "category")
		assert.True(t, hasXPathContextEvidence(rr, ip, "/catalog", "<html>x</html>"))
	})

	t.Run("request soap content-type", func(t *testing.T) {
		rr := withRequestContentType(t, modtest.Request(t, "http://x.test/svc?q=1"), "application/soap+xml")
		ip := modtest.InsertionPoint(t, rr, "q")
		assert.True(t, hasXPathContextEvidence(rr, ip, "/svc", "<html>x</html>"))
	})

	t.Run("xml baseline body", func(t *testing.T) {
		rr := modtest.Request(t, "http://x.test/catalog?category=Gin")
		ip := modtest.InsertionPoint(t, rr, "category")
		assert.True(t, hasXPathContextEvidence(rr, ip, "/catalog", `<?xml version="1.0"?><catalog/>`))
	})

	t.Run("web-service path marker", func(t *testing.T) {
		rr := modtest.Request(t, "http://x.test/services/lookup?category=Gin")
		ip := modtest.InsertionPoint(t, rr, "category")
		assert.True(t, hasXPathContextEvidence(rr, ip, "/services/lookup", "<html>x</html>"))
	})

	t.Run("xml parameter name", func(t *testing.T) {
		rr := modtest.Request(t, "http://x.test/q?xpath=foo")
		ip := modtest.InsertionPoint(t, rr, "xpath")
		assert.True(t, hasXPathContextEvidence(rr, ip, "/q", "<html>x</html>"))
	})

	t.Run("no evidence: html page, generic param", func(t *testing.T) {
		rr := modtest.Response(modtest.Request(t, "http://x.test/catalog?category=Gin"), "text/html", "<html/>")
		ip := modtest.InsertionPoint(t, rr, "category")
		assert.False(t, hasXPathContextEvidence(rr, ip, "/catalog", "<html>x</html>"))
	})
}

// withRequestContentType rebuilds rr's request carrying an explicit Content-Type header,
// so the request-side XML/SOAP content-type signal can be exercised.
func withRequestContentType(t *testing.T, rr *httpmsg.HttpRequestResponse, ct string) *httpmsg.HttpRequestResponse {
	t.Helper()
	req := rr.Request().WithHeader("Content-Type", ct)
	require.NotNil(t, req)
	return httpmsg.NewHttpRequestResponse(req, rr.Response())
}
