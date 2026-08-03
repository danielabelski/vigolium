package infra

// Shared cache/reverse-proxy oracle.
//
// Several modules need to answer the same two infrastructure questions from a
// response's headers: "is there a shared cache / CDN / reverse proxy in front of
// the origin?" and "was this particular response served from that cache?".
// CacheState centralizes that header parsing so cache-aware active modules
// (e.g. cache-poisoned-dos) and the RQP-amplification check below agree on the
// signals instead of each re-implementing an ad-hoc X-Cache/Age/CF heuristic.

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// CacheInfo summarizes the cache/proxy signals observed in a response's headers.
type CacheInfo struct {
	// Hit is true when the response was served from a cache — an explicit HIT
	// marker (X-Cache / CF-Cache-Status / X-Cache-Status) or a non-zero Age.
	Hit bool
	// Age is the parsed Age header in seconds, or -1 when absent/unparseable.
	Age int
	// Layer is true when any caching / CDN / reverse-proxy fingerprint header is
	// present — i.e. there is a shared cache or proxy in front of the origin.
	Layer bool
	// Evidence names the strongest cache-hit signal observed, for use in findings.
	Evidence string
}

// hitHeaders carry an explicit cache hit/miss status; a value containing "HIT"
// means the response was served from cache. (X-Cache may be multi-valued, e.g.
// Fastly's "HIT, MISS", so a substring match is intentional.)
var hitHeaders = []string{"X-Cache", "CF-Cache-Status", "X-Cache-Status"}

// cacheLayerHeaders are additional response headers whose mere presence betrays a
// caching layer or CDN / reverse proxy. The hit-indicating headers and Age are
// inspected separately in CacheState.
var cacheLayerHeaders = []string{
	"X-Cache-Hits", "Via", "X-Served-By", "X-Amz-Cf-Id", "X-Varnish",
	"X-Fastly-Request-Id", "Fastly-Debug-Digest", "X-Akamai-Transformed",
}

// Lowercased lookup sets derived from the slices above, so the single-pass
// CacheStateFromHeaders can classify a header by one map lookup instead of an
// EqualFold sweep. Single source of truth: edit the slices, the sets follow.
var (
	hitHeaderSet        = lowerSet(hitHeaders)
	cacheLayerHeaderSet = lowerSet(cacheLayerHeaders)
)

func lowerSet(names []string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[strings.ToLower(n)] = struct{}{}
	}
	return m
}

// CacheStateFromHeaders is the single-pass form of CacheState for callers that
// hold the parsed header slice (an *httpmsg.HttpResponse). It walks the headers
// once, classifying each by a map lookup, instead of issuing ~12 case-insensitive
// getter lookups that each rescan the whole header list — the shape CacheState
// must use when it only has a getter. Equivalent result; Evidence is taken from
// the first hit signal in response order.
func CacheStateFromHeaders(headers []httpmsg.HttpHeader) CacheInfo {
	info := CacheInfo{Age: -1}
	for _, h := range headers {
		name := strings.ToLower(h.Name)
		if _, ok := hitHeaderSet[name]; ok {
			info.Layer = true
			if strings.Contains(strings.ToUpper(h.Value), "HIT") {
				info.Hit = true
				if info.Evidence == "" {
					info.Evidence = h.Name + ": " + h.Value
				}
			}
			continue
		}
		if name == "age" {
			info.Layer = true
			if n, err := strconv.Atoi(strings.TrimSpace(h.Value)); err == nil {
				info.Age = n
				if n > 0 {
					info.Hit = true
					if info.Evidence == "" {
						info.Evidence = "Age: " + h.Value
					}
				}
			}
			continue
		}
		if _, ok := cacheLayerHeaderSet[name]; ok {
			info.Layer = true
		}
	}
	return info
}

// CacheState inspects response headers via a case-insensitive getter (such as
// net/http.Header.Get or httpmsg.HttpResponse.Header) and reports cache signals.
// It never sends traffic — it only interprets headers already in hand.
func CacheState(get func(name string) string) CacheInfo {
	info := CacheInfo{Age: -1}
	if get == nil {
		return info
	}

	for _, name := range hitHeaders {
		v := get(name)
		if v == "" {
			continue
		}
		info.Layer = true
		if strings.Contains(strings.ToUpper(v), "HIT") {
			info.Hit = true
			if info.Evidence == "" {
				info.Evidence = name + ": " + v
			}
		}
	}

	if age := get("Age"); age != "" {
		info.Layer = true
		if n, err := strconv.Atoi(strings.TrimSpace(age)); err == nil {
			info.Age = n
			if n > 0 {
				info.Hit = true
				if info.Evidence == "" {
					info.Evidence = "Age: " + age
				}
			}
		}
	}

	if !info.Layer {
		for _, name := range cacheLayerHeaders {
			if get(name) != "" {
				info.Layer = true
				break
			}
		}
	}
	return info
}

// rqpProxyServers are Server-header tokens for pooling front-ends / reverse
// proxies known to reuse upstream keep-alive connections — the substrate a
// Response Queue Poisoning attack rides on.
var rqpProxyServers = []string{
	"nginx", "varnish", "haproxy", "envoy", "cloudflare",
	"awselb", "apache traffic server", "ats/", "openresty",
}

// RQPAmplification reports whether a confirmed header/response injection on this
// response sits behind conditions that make Response Queue Poisoning (RQP)
// plausible, and returns a short evidence string. It does NOT confirm live RQP —
// that requires a cross-user probe we deliberately avoid — it only flags the
// amplification precondition so a confirmed CRLF/header-injection finding can be
// escalated by the caller.
//
// Returns (true, evidence) only when all three hold:
//   - the response is HTTP/1.1 (RQP is a connection-reuse attack; HTTP/2 stream
//     multiplexing changes the model and is excluded),
//   - the connection is keep-alive (the HTTP/1.1 default, absent Connection: close),
//   - a caching / CDN / reverse-proxy layer is fingerprinted in front of the origin.
func RQPAmplification(resp *httpmsg.HttpResponse) (bool, string) {
	if resp == nil {
		return false, ""
	}

	// HTTP/1.1 only — read the protocol from the raw response status line.
	if !bytes.HasPrefix(resp.Raw(), []byte("HTTP/1.1")) {
		return false, ""
	}

	// Keep-alive: HTTP/1.1 reuses the connection by default unless told to close.
	if strings.Contains(strings.ToLower(resp.Header("Connection")), "close") {
		return false, ""
	}

	// A pooling front-end (cache/CDN/reverse proxy) must be present, otherwise
	// there is no shared connection queue to poison.
	var evidence []string
	if CacheStateFromHeaders(resp.Headers()).Layer {
		evidence = append(evidence, "cache/proxy headers")
	}
	server := strings.ToLower(resp.Header("Server"))
	for _, s := range rqpProxyServers {
		if strings.Contains(server, s) {
			evidence = append(evidence, "Server: "+resp.Header("Server"))
			break
		}
	}
	if len(evidence) == 0 {
		return false, ""
	}

	return true, "HTTP/1.1 keep-alive behind a pooling front-end (" + strings.Join(evidence, ", ") + ")"
}

// CacheMaxAge extracts the freshness lifetime a Cache-Control header grants,
// in seconds. ok is false when no max-age directive is present or its value does
// not parse.
//
// This lives here, alongside the rest of the cache-header parsing, so the
// cache-aware modules agree on the directive's meaning: bfla-detection reads it
// to recognise a shipped static artifact (long TTL ⇒ one representation for
// every caller, so no authorization conclusion can be drawn), while
// web-cache-poisoning reads it to decide whether a response is cacheable at all.
// cc is matched case-insensitively; the leading start-or-separator anchor keeps
// the pattern off the tail of the shared-cache directive `s-maxage`.
func CacheMaxAge(cc string) (int, bool) {
	m := cacheMaxAgeRe.FindStringSubmatch(cc)
	if m == nil {
		return 0, false
	}
	age, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return age, true
}

var cacheMaxAgeRe = regexp.MustCompile(`(?i)(?:^|[\s,])max-age\s*=\s*"?(\d+)`)
