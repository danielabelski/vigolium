package aspnet_service_exposure

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	sev         severity.Severity
	desc        string
	// structured marks a probe whose genuine hit is a structured XML document (an
	// OData $metadata EDMX) — never an HTML *document*. It enables content-type
	// discipline that survives the catch-all/echo body-truncation FP: a gzip + bogus
	// Content-Length:0 quirk can leave only a partial body tail (no <!DOCTYPE/<html>),
	// defeating body anti-markers and shell-similarity guards, but the Content-Type
	// header is intact. A reflecting/catch-all host that answers ANY path with its
	// themed text/html shell would forge a match on a weak marker ("EntityType") in
	// that tail; rejecting an HTML document for an XML probe costs no true positives.
	// The SharePoint/Services directory-listing probes genuinely render HTML, so they
	// leave this false and rely on the decoy catch-all disproof instead.
	structured bool
}

// accepts reports whether body satisfies this probe's marker requirement (any
// single marker present). Centralized so the primary match and the multi-round
// catch-all decoy disproof apply the exact same predicate to the candidate and to
// the negative-control siblings.
func (p probe) accepts(body string) (matched []string, ok bool) {
	for _, marker := range p.markers {
		if strings.Contains(body, marker) {
			matched = append(matched, marker)
		}
	}
	return matched, len(matched) > 0
}

var commonProbes = []probe{
	{
		path:        "/odata/$metadata",
		name:        "OData Metadata",
		markers:     []string{"<edmx:Edmx", "EntityType"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "OData service metadata endpoint exposed, revealing entity data model and available operations",
		structured:  true, // OData $metadata is an XML EDMX document, never HTML
	},
	{
		path:        "/api/odata/$metadata",
		name:        "API OData Metadata",
		markers:     []string{"<edmx:Edmx", "EntityType"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "OData service metadata endpoint exposed under /api path, revealing entity data model",
		structured:  true, // OData $metadata is an XML EDMX document, never HTML
	},
	{
		path: "/_vti_bin/",
		name: "SharePoint VTI Bin",
		// A bare "<pre>" was dropped: it is a generic HTML tag that a benign 200
		// page at this route can carry, and an ANY-of match on it reported a
		// "directory listing exposed" on pages that were not listings. A genuine
		// IIS/SharePoint listing is identified by the parent-directory / index
		// phrasing or the listed service-file extensions.
		markers:     []string{"Parent Directory", "Index of", ".asmx"},
		antiMarkers: []string{"404", "Not Found", "403", "Forbidden"},
		sev:         severity.Medium,
		desc:        "SharePoint _vti_bin directory exposed, revealing available web service endpoints",
	},
	{
		path:        "/Services/",
		name:        "Services Directory",
		markers:     []string{"Parent Directory", "Index of", ".svc", ".asmx"},
		antiMarkers: []string{"404", "Not Found", "403", "Forbidden"},
		sev:         severity.Low,
		desc:        "ASP.NET Services directory listing exposed, revealing available web service files",
	},
}

// WSDL markers for .asmx and .svc endpoints
var wsdlMarkers = []string{"<wsdl:definitions", "<definitions", "wsdl:types", "wsdl:portType"}
var discoMarkers = []string{"<discovery", "<contractRef", "<discoveryRef"}
var wcfFaultMarkers = []string{"<ExceptionDetail>", "<StackTrace>", "includeExceptionDetailInFaults"}
