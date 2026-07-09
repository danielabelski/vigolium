package rails_admin_dashboard

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

type probe struct {
	path        string
	name        string
	markers     []string
	antiMarkers []string
	// htmlDoc marks a probe whose GENUINE hit is a rendered HTML document (a Rails
	// admin panel / job-dashboard UI). Those cannot use the content-type=HTML
	// rejection (their real content IS text/html), so they lean on the decoy /
	// status catch-all confirmation instead. When false the probe targets a
	// non-document resource (rack-mini-profiler's includes.js) that is never
	// served as an HTML document, so the truncation-proof content-type gate
	// applies.
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
		path:    "/sidekiq",
		name:    "Sidekiq Web UI",
		markers: []string{"Sidekiq"},
		htmlDoc: true,
		sev:     severity.High,
		desc:    "Sidekiq Web UI is exposed, revealing background job queues, retry data, and potentially sensitive job arguments",
	},
	{
		path:    "/admin/sidekiq",
		name:    "Sidekiq Web UI (admin path)",
		markers: []string{"Sidekiq"},
		htmlDoc: true,
		sev:     severity.High,
		desc:    "Sidekiq Web UI is exposed at admin path",
	},
	{
		path:    "/good_job",
		name:    "GoodJob Dashboard",
		markers: []string{"GoodJob"},
		htmlDoc: true,
		sev:     severity.High,
		desc:    "GoodJob dashboard is exposed, revealing job payloads and schedules",
	},
	{
		path:    "/resque",
		name:    "Resque Dashboard",
		markers: []string{"Resque"},
		htmlDoc: true,
		sev:     severity.High,
		desc:    "Resque dashboard is exposed, revealing background job data and worker status",
	},
	{
		path:    "/delayed_job",
		name:    "Delayed Job Dashboard",
		markers: []string{"Delayed::Job", "Delayed Job"},
		htmlDoc: true,
		sev:     severity.High,
		desc:    "Delayed Job dashboard is exposed",
	},
	{
		path:    "/mini-profiler-resources/includes.js",
		name:    "rack-mini-profiler",
		markers: []string{"MiniProfiler"},
		// A JavaScript include, never an HTML document → content-type discipline.
		htmlDoc: false,
		sev:     severity.Medium,
		desc:    "rack-mini-profiler is enabled, potentially exposing performance traces, SQL queries, and internal timing data",
	},
	{
		path:        "/admin",
		name:        "ActiveAdmin Panel",
		markers:     []string{"Active Admin", "activeadmin", "active_admin"},
		antiMarkers: []string{"WordPress", "wp-login", "Joomla", "Drupal"},
		htmlDoc:     true,
		sev:         severity.High,
		desc:        "ActiveAdmin panel is accessible, potentially allowing administrative operations",
	},
	{
		path:    "/rails_admin",
		name:    "RailsAdmin Panel",
		markers: []string{"RailsAdmin", "rails_admin"},
		htmlDoc: true,
		sev:     severity.High,
		desc:    "RailsAdmin panel is accessible, potentially allowing full administrative control",
	},
	{
		path:    "/active_admin",
		name:    "ActiveAdmin Panel (alternate path)",
		markers: []string{"Active Admin", "activeadmin", "active_admin"},
		htmlDoc: true,
		sev:     severity.High,
		desc:    "ActiveAdmin panel is accessible at alternate path",
	},
}
