package aspnet_blazor_exposure

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	// htmlDoc marks a probe whose GENUINE hit is a rendered HTML document (the
	// /_content directory listing). Those cannot use the content-type=HTML
	// rejection (their real content IS text/html), so they lean on the decoy /
	// status catch-all confirmation instead. When false the probe targets a
	// structured resource — a JSON boot/negotiate manifest, a JavaScript runtime,
	// or the .NET WASM binary — that is never served as an HTML document, so the
	// truncation-proof content-type gate applies.
	htmlDoc bool
	sev     severity.Severity
	desc    string
}

// accepts reports whether body carries at least one of this probe's markers.
// Centralized so the primary match and the catch-all decoy disproof run the
// exact same predicate against the candidate and the decoy sibling.
func (p probe) accepts(body string) (matched []string, ok bool) {
	for _, marker := range p.markers {
		if strings.Contains(body, marker) {
			matched = append(matched, marker)
		}
	}
	return matched, len(matched) > 0
}

// markerMatch is the flat-body predicate handed to MultiRoundExtDecoyCatchAll.
func (p probe) markerMatch(body string) bool {
	_, ok := p.accepts(body)
	return ok
}

var probes = []probe{
	{
		path:        "/_framework/blazor.boot.json",
		name:        "Blazor WASM Boot Manifest",
		markers:     []string{"assembly", "resources", "mainAssemblyName", "linkerEnabled"},
		antiMarkers: []string{"404", "Not Found"},
		htmlDoc:     false, // application/json manifest
		sev:         severity.High,
		desc:        "Blazor WebAssembly boot manifest exposed, listing all .NET assemblies available for download and decompilation",
	},
	{
		path:        "/_framework/blazor.webassembly.js",
		name:        "Blazor WASM Runtime",
		markers:     []string{"Blazor", "blazor", "WebAssembly", "_framework"},
		antiMarkers: []string{"404", "Not Found"},
		htmlDoc:     false, // JavaScript runtime
		sev:         severity.Low,
		desc:        "Blazor WebAssembly runtime JavaScript accessible, confirming Blazor WASM deployment",
	},
	{
		path:        "/_framework/blazor.server.js",
		name:        "Blazor Server Runtime",
		markers:     []string{"Blazor", "blazor", "signalR", "HubConnection"},
		antiMarkers: []string{"404", "Not Found"},
		htmlDoc:     false, // JavaScript runtime
		sev:         severity.Low,
		desc:        "Blazor Server runtime JavaScript accessible, confirming Blazor Server deployment",
	},
	{
		path:        "/_blazor/negotiate",
		name:        "Blazor Server Hub Negotiate",
		markers:     []string{"connectionId", "connectionToken", "negotiateVersion", "availableTransports"},
		antiMarkers: []string{"404", "Not Found"},
		htmlDoc:     false, // application/json negotiate response
		sev:         severity.Medium,
		desc:        "Blazor Server SignalR hub negotiate endpoint exposed, revealing real-time communication infrastructure details",
	},
	{
		path:        "/_content/",
		name:        "Blazor Content Directory",
		markers:     []string{"<pre>", "Parent Directory", "Index of", "<DIR>"},
		antiMarkers: []string{"404", "Not Found", "403", "Forbidden"},
		htmlDoc:     true, // a directory listing is a genuine HTML document
		sev:         severity.Medium,
		desc:        "Blazor Razor component library content directory listing exposed",
	},
	{
		path:        "/_framework/dotnet.wasm",
		name:        "Blazor .NET WASM Runtime",
		markers:     []string{"\x00asm"}, // WebAssembly magic bytes
		antiMarkers: []string{"404", "Not Found"},
		htmlDoc:     false, // application/wasm binary
		sev:         severity.Low,
		desc:        "Blazor .NET WebAssembly runtime binary accessible, confirming Blazor WASM deployment",
	},
}
