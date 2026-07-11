package xpath_injection

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// xmlContextPathMarkers are path fragments that indicate an XML/SOAP/XPath-backed
// endpoint — the surface where an XPath/XQuery sink realistically lives. Compared
// case-insensitively.
var xmlContextPathMarkers = []string{
	"soap", "wsdl", "xmlrpc", "xml-rpc", "/services/", "/service/", "/ws/",
	"xpath", "xquery", "/rss", "/atom", "/feed", "sitemap", ".xml", "/xml", "saml",
}

// xmlContextParamNames are parameter names whose intent is unambiguously XML/XPath —
// the app is selecting among XML nodes. Compared case-insensitively (exact match).
var xmlContextParamNames = map[string]bool{
	"xml": true, "xpath": true, "xquery": true, "xpathexpr": true,
	"xmldoc": true, "xnode": true, "xsl": true, "xslt": true, "node": true,
	"doc": true, "soap": true, "xmlrequest": true, "xmlresponse": true,
}

// hasXPathContextEvidence reports whether the request/response context is plausibly
// backed by an XML/XPath/XQuery engine — the precondition for running the FP-prone
// boolean-oracle leg. XPath's boolean payloads (' or '1'='1) are indistinguishable at
// the HTTP layer from SQL's, so on a generic HTML endpoint a SQL injection reproduces
// the exact oracle (the ginandjuice.shop `category` false positive). Requiring positive
// XML/XPath evidence — an XML/SOAP content-type on the request or response, an XML/SOAP
// document body, a web-service/XPath path, or an XML/XPath parameter name — confines the
// boolean leg to endpoints where an XPath sink can actually exist. The error-based leg
// is deliberately NOT gated on this: an engine-specific XPath error string
// (javax.xml.xpath.*, net.sf.saxon.*, …) is self-corroborating wherever it appears.
func hasXPathContextEvidence(ctx *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, path, baselineBody string) bool {
	// Cheap header/path/param checks first; the body sniffs (which trim + lowercase a
	// potentially large baseline) run last so a match on any cheap signal short-circuits.

	// 1) Response Content-Type — the strongest signal in a real scan. The executor
	//    supplies the captured baseline response here even though the module refetches
	//    the body itself for comparison.
	if resp := ctx.Response(); resp != nil && isXMLMediaType(resp.Header("Content-Type")) {
		return true
	}
	// 2) Request Content-Type — a SOAP or XML POST is a direct XPath surface.
	if req := ctx.Request(); req != nil && isXMLMediaType(req.Header("Content-Type")) {
		return true
	}
	// 3) Path marker — web service / XPath / feed endpoint.
	lp := strings.ToLower(path)
	for _, mk := range xmlContextPathMarkers {
		if strings.Contains(lp, mk) {
			return true
		}
	}
	// 4) Parameter name is an XML/XPath selector.
	if ip != nil && xmlContextParamNames[strings.ToLower(ip.Name())] {
		return true
	}
	// 5) Request body is an XML/SOAP document (body sniff — after the cheap checks).
	if req := ctx.Request(); req != nil && looksLikeXMLBody(req.BodyToString()) {
		return true
	}
	// 6) The fetched baseline body is itself an XML/SOAP document (largest sniff last).
	return looksLikeXMLBody(baselineBody)
}

// isXMLMediaType reports whether a Content-Type value is an XML-family media type
// (application/xml, text/xml, application/soap+xml, application/rss+xml,
// application/atom+xml, …). It delegates to the shared modkit classifier, which treats
// XHTML as HTML (checked before XML) — so XHTML is excluded, as intended: it is HTML
// delivered as XML, not an XPath-sink signal, and counting it would re-open the very FP
// class this gate exists to close on ordinary web pages.
func isXMLMediaType(ct string) bool {
	return modkit.ClassifyContentType(ct) == modkit.ContentClassXML
}

// looksLikeXMLBody reports whether body is (the start of) an XML or SOAP document.
// Conservative on purpose: only an explicit XML prolog or a SOAP envelope counts, so an
// HTML document or fragment (which also starts with '<') is never mistaken for XML. Only
// the leading 1024 bytes are inspected — an XML prolog/SOAP envelope always appears at
// the very top — so the lowercase allocation stays bounded on large baseline bodies.
func looksLikeXMLBody(body string) bool {
	t := strings.TrimSpace(body)
	if t == "" {
		return false
	}
	if len(t) > 1024 {
		t = t[:1024]
	}
	lower := strings.ToLower(t)
	if strings.HasPrefix(lower, "<?xml") {
		return true
	}
	if strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") {
		return false
	}
	return strings.HasPrefix(lower, "<soap") ||
		strings.Contains(lower, "<soap:envelope") ||
		strings.Contains(lower, "<soapenv:envelope") ||
		strings.Contains(lower, "xmlns:soap")
}
