package secret_detect

// urlSlugScanBack bounds how far back from a match the enclosing-URL scan walks
// looking for "://". No real URL puts a path segment more than this many bytes
// after its scheme, and the cap keeps the guard O(1) on the secret-scan hot path
// even when the match sits in a minified bundle with no nearby delimiter.
const urlSlugScanBack = 512

// IsURLPathSlugMatch reports whether the matched secret is a hyphenated word slug
// occupying a path segment of an absolute URL in the body — a link, not a credential.
//
// This is the failure mode of every provider PROXIMITY rule, whose pattern is
// "<vendor keyword> within N characters of <fixed-width charclass>". The vendor's
// own URL satisfies both halves at once: the keyword matches the hostname and the
// article slug in the path matches the charclass. The New York Times rule
// (`(?i)(?:nytimes|new[- ]?york[- ]?times).{0,32}?\b([a-z0-9_\-=]{32})\b`) fires on
// an ordinary press-mention hyperlink —
//
//	<a href="https://www.nytimes.com/2025/01/23/arts/what-to-do-nyc-arts-january-2025.html">
//
// capturing the 32-character slug `what-to-do-nyc-arts-january-2025` and grading it
// a High-severity leaked API key. The keyword and the "secret" came from the same
// href.
//
// Two independent conditions must both hold, which is what keeps a real
// URL-embedded secret safe:
//
//   - The value has dictionary-slug shape (isWordSlug): '-'-delimited segments that
//     are each purely letters or purely digits, with at least two real words. A
//     Slack webhook token, a Discord webhook token, a UUID, and any base64/hex key
//     all carry mixed-alphanumeric or symbol-bearing segments and fail this.
//   - It sits in the PATH of an absolute URL — preceded by '/', with "://" behind it
//     and no '?' or '#' in between (see inAbsoluteURLPath). Secrets that legitimately
//     live in a URL — presigned S3 signatures, signed CDN tokens, API keys passed as
//     parameters — are query-string values, so the path-only scope excludes them.
func IsURLPathSlugMatch(body []byte, snippet string, start, end int) bool {
	// Shape first: it is an allocation-free scan of the snippet that rejects almost
	// every match, while resolveMatchSpan may fall back to a full-body bytes.Index.
	if !isWordSlug(snippet) {
		return false
	}
	idx, matchEnd, ok := resolveMatchSpan(body, snippet, start, end)
	if !ok {
		return false
	}
	// The capture must be a whole path segment, not a slice of a longer token: the
	// byte before is the '/' separator and the byte after ends the segment (a '/',
	// an extension/'.'-separator, a query/fragment start, or the quote/angle bracket
	// closing the attribute).
	if idx == 0 || body[idx-1] != '/' {
		return false
	}
	if matchEnd < len(body) && !isSegmentBoundary(body[matchEnd]) {
		return false
	}
	return inAbsoluteURLPath(body, idx)
}

// isSegmentBoundary reports whether b can terminate a URL path segment: the next
// separator, an extension dot, the start of a query/fragment, or the delimiter
// closing the surrounding attribute/string literal. Any other byte means the match
// is only part of a longer token, so the caller is not looking at a whole segment.
func isSegmentBoundary(b byte) bool {
	switch b {
	case '/', '.', '?', '#', '"', '\'', '`', '<', '>', '\\', ' ', '\t', '\n', '\r', ')':
		return true
	}
	return false
}

// isWordSlug reports whether s is a hyphenated dictionary-word slug — the shape of
// a CMS article/page path segment like `what-to-do-nyc-arts-january-2025`.
//
// Every '-'-delimited segment must be non-empty and either all letters or all
// digits, and at least two must be letter words of 3+ characters. A single
// mixed-alphanumeric segment (`w4Kb`, a hex byte pair, a base64 run) or any other
// character (`_`, '.', '=') disqualifies the value outright — which is what keeps
// this off real credentials, since opaque tokens are mixed by construction and a
// UUID's segments are hex. Requiring two spelled-out words keeps it off short
// hyphenated identifiers.
func isWordSlug(s string) bool {
	// Walk the '-'-delimited segments in place — this runs on every untrusted match,
	// so it must not allocate. Counting words alone is enough: every word increments
	// within an iteration that also saw a segment, so two words imply two segments
	// (and an empty input yields one empty segment, rejected below).
	words, start := 0, 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '-' {
			continue
		}
		seg := s[start:i]
		start = i + 1
		hasLetter, hasDigit, hasOther := segClass(seg)
		// An empty segment (a leading, trailing, or doubled '-') is not a word slug,
		// and neither is a mixed or symbol-bearing one.
		if seg == "" || hasOther || (hasLetter && hasDigit) {
			return false
		}
		if hasLetter && len(seg) >= 3 {
			words++
		}
	}
	return words >= 2
}

// inAbsoluteURLPath reports whether the byte at idx lies in the path of an absolute
// URL literal — i.e. scanning back from idx reaches a "://" before any character
// that cannot appear inside a URL, and without crossing a '?' or '#'.
//
// The backward scan stops at whitespace, quotes, angle brackets, and the other
// delimiters that bound a URL inside HTML/JS/JSON, so it never runs out of one
// literal and into a neighbouring one. Crossing '?' or '#' means idx is in the
// query or fragment rather than the path, which is where URL-borne secrets actually
// live — so the caller must not treat those as links. The scan is capped at
// urlSlugScanBack bytes.
func inAbsoluteURLPath(body []byte, idx int) bool {
	limit := idx - urlSlugScanBack
	if limit < 0 {
		limit = 0
	}
	for i := idx; i > limit; i-- {
		switch body[i-1] {
		case '?', '#':
			// In the query/fragment, not the path.
			return false
		case ':':
			// The scheme separator — "://" with the two slashes already behind us.
			return i+1 < len(body) && body[i] == '/' && body[i+1] == '/'
		case ' ', '\t', '\n', '\r', '"', '\'', '`', '<', '>', '(', ')', '[', ']', '{', '}', ',', ';', '\\':
			// Left the URL literal without finding a scheme.
			return false
		}
	}
	return false
}
