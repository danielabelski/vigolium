package waf

import (
	"net/http"
	"strings"
)

// EdgeFront returns the slug of the CDN/WAF edge fronting a host, inferred from
// response headers that are present on ORDINARY (non-block) responses — e.g. a
// clean 200. It returns "" when no known edge is fingerprinted.
//
// This is deliberately distinct from ClassifyParts, which only fires on a block
// response. EdgeFront answers a different question — "is this host behind an edge
// that could arm a rate-based WAF once a scan bursts it?" — so the scanner can pace
// that host's active phase BEFORE it trips the edge, rather than only reacting after
// the first block (by which point the burst has already armed the WAF). The curated
// set is the major WAF-capable edges (CloudFront, Cloudflare, Akamai,
// Imperva/Incapsula, Sucuri, Azure Front Door), keyed on vendor-specific presence
// headers that ride on every response from that edge. A plain origin or a bare CDN
// passthrough that sets none of these is not paced.
func EdgeFront(header http.Header) string {
	if len(header) == 0 {
		return ""
	}
	// Fetch + lowercase the Server value once (several vendors key on it) rather than
	// re-Get/re-lowercase it per case as the switch falls through.
	server := strings.ToLower(header.Get("Server"))
	switch {
	case headerHas(header, "Cf-Ray"), headerHas(header, "Cf-Mitigated"), strings.Contains(server, "cloudflare"):
		return "cloudflare"
	case headerHas(header, "X-Amz-Cf-Id"), headerContains(header, "Via", "cloudfront"):
		return "cloudfront"
	case headerHas(header, "X-Akamai-Transformed"), headerHas(header, "Akamai-Origin-Hop"), strings.Contains(server, "akamaighost"):
		return "akamai"
	case headerHas(header, "X-Iinfo"), headerContains(header, "X-Cdn", "incapsula"), headerContains(header, "X-Cdn", "imperva"):
		return "imperva"
	case headerHas(header, "X-Sucuri-Id"), headerHas(header, "X-Sucuri-Cache"), strings.Contains(server, "sucuri"):
		return "sucuri"
	case headerHas(header, "X-Azure-Ref"):
		return "azure_frontdoor"
	}
	return ""
}

// headerHas reports whether the response carries a non-empty value for the named
// header (http.Header canonicalizes the key on lookup). These fingerprint headers
// always carry a value, so a non-empty Get is a sound presence check.
func headerHas(h http.Header, key string) bool {
	return h.Get(key) != ""
}

// headerContains reports whether the named header's value contains sub
// (case-insensitive). sub must already be lowercase.
func headerContains(h http.Header, key, sub string) bool {
	v := h.Get(key)
	return v != "" && strings.Contains(strings.ToLower(v), sub)
}
