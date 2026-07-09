package aspnet_misconfig

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
	// jsonBody marks a probe whose genuine hit is a structured JSON/JS document (the
	// SignalR negotiate JSON, the SignalR hubs script) — never an HTML *document*.
	// It enables content-type discipline that survives the catch-all/echo body-
	// truncation FP: a gzip + bogus Content-Length:0 quirk can leave only a partial
	// body tail (no <!DOCTYPE/<html>), defeating body anti-markers and shell-
	// similarity guards, but the Content-Type header is intact. A reflecting/catch-
	// all host that answers ANY path with its themed text/html shell would forge a
	// match on a weak marker ("connectionId") in that tail; rejecting an HTML
	// document for a JSON/JS probe is decisive and costs no true positives. The
	// diagnostic dashboards (trace/elmah/glimpse/hangfire/miniprofiler) genuinely
	// render HTML, so they leave this false and rely on the decoy catch-all disproof.
	jsonBody bool
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

var probes = []probe{
	{
		path:        "/trace.axd",
		name:        "ASP.NET Trace",
		markers:     []string{"Application Trace", "Request Details", "Trace Information"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.High,
		desc:        "ASP.NET trace handler is exposed, revealing detailed request/response information and application internals",
	},
	{
		path:        "/elmah.axd",
		name:        "ELMAH Error Log",
		markers:     []string{"ELMAH", "Error Log for", "Error Filtering"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.High,
		desc:        "ELMAH error logging handler is exposed, revealing application errors, stack traces, and server details",
	},
	{
		path:        "/glimpse.axd",
		name:        "Glimpse Diagnostics",
		markers:     []string{"Glimpse", "glimpseData"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "Glimpse diagnostics endpoint is exposed, revealing server-side execution details",
	},
	{
		path:        "/glimpse",
		name:        "Glimpse Diagnostics",
		markers:     []string{"Glimpse", "glimpseData"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "Glimpse diagnostics endpoint is exposed, revealing server-side execution details",
	},
	{
		path:        "/mini-profiler-resources/results",
		name:        "MiniProfiler",
		markers:     []string{"MiniProfiler", "profiler"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "MiniProfiler results endpoint is exposed, revealing SQL queries and performance data",
	},
	{
		path:        "/hangfire",
		name:        "Hangfire Dashboard",
		markers:     []string{"Hangfire", "hangfire", "Dashboard"},
		antiMarkers: []string{"404", "Not Found", "login", "Login"},
		sev:         severity.High,
		desc:        "Hangfire background job dashboard is publicly accessible, potentially allowing job manipulation",
	},
	{
		path:        "/signalr/negotiate",
		name:        "SignalR Negotiate",
		markers:     []string{"connectionId", "negotiateVersion"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "SignalR negotiate endpoint is exposed, revealing real-time communication infrastructure",
		jsonBody:    true, // negotiate returns a JSON handshake, never an HTML document
	},
	{
		path:        "/signalr/hubs",
		name:        "SignalR Hubs",
		markers:     []string{"signalR", "hubConnection"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "SignalR hubs endpoint is exposed, revealing available real-time communication hubs",
		jsonBody:    true, // hubs is a generated JavaScript proxy, never an HTML document
	},
}
