package aem

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// HasAll reports whether body contains every substring in subs.
func HasAll(body string, subs ...string) bool {
	for _, s := range subs {
		if !strings.Contains(body, s) {
			return false
		}
	}
	return true
}

// HasAny reports whether body contains at least one substring in subs.
func HasAny(body string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(body, s) {
			return true
		}
	}
	return false
}

// IsJSONContentType reports whether a Content-Type value denotes JSON.
func IsJSONContentType(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "json")
}

// HostFromBase returns the authority of a "scheme://host" base URL.
func HostFromBase(baseURL string) string {
	return strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
}

// ServletResponded reports whether status looks like a real servlet handler that
// processed the request (typically erroring on a missing parameter) rather than a
// not-present 404 or an auth/redirect gate. Shared by the reachability checks
// (aem_ssrf, aem_rce).
func ServletResponded(status int) bool {
	switch status {
	case 200, 400, 405, 500:
		return true
	default:
		return false
	}
}

// SiblingIs404 fetches a guaranteed-nonexistent sibling under path's parent
// directory and reports whether it 404s — proving path is a specific servlet
// mount rather than a wildcard/catch-all. Fails closed (returns false) for a
// root-level path, a probe error, or any non-404 sibling.
func SiblingIs404(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string) bool {
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return false // root-level: no same-parent sibling to differentiate
	}
	res := Get(ctx, client, path[:i]+"/"+modkit.FreshCanary(), nil)
	return res.OK && res.Status == 404
}

// ServletPresent reports whether path is a specific servlet mount on the AEM host:
// it responds like a handler (ServletResponded) AND a random sibling under the same
// parent directory 404s (SiblingIs404), ruling out a wildcard/catch-all that answers
// every path. The shared reachability gate for detection-only and blind probes.
func ServletPresent(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string) bool {
	res := Get(ctx, client, path, nil)
	if !res.OK || !ServletResponded(res.Status) {
		return false
	}
	return SiblingIs404(ctx, client, path)
}

// ACLBypassTag returns the dispatcher-bypass finding tag when a finding was reached
// through a bypass variant (rather than the clean path), and nil otherwise — the
// shared "isBypass → acl-bypass tag" rule used by the AEM module builders.
func ACLBypassTag(isBypass bool) []string {
	if isBypass {
		return []string{"acl-bypass"}
	}
	return nil
}
