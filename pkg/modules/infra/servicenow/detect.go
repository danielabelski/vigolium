// Package servicenow holds shared detection and Service Portal widget helpers for
// the servicenow_* scanner family.
//
// The exposure class is a public Service Portal widget (Simple List / Unordered
// List / KB Article Page) that wraps a GlideRecordSecure query over an
// attacker-supplied table/field. Because the widgets are not ACL-protected and
// many out-of-the-box table ACLs resolve to "allow-all", an unauthenticated
// (guest) caller can read arbitrary tables. This package centralizes the guest
// session/CSRF-token acquisition (AcquireSession, which doubles as the fail-closed
// presence gate), the widget POST helper, and the response classification.
package servicenow

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/saasprobe"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Tag is the tech-stack tag published for ServiceNow hosts.
const Tag = "servicenow"

// VendorHostSuffixes are default ServiceNow-hosted domains.
var VendorHostSuffixes = []string{".service-now.com"}

// strongCookieNames are ServiceNow-specific session cookies. Any one is a strong
// signal (they are not emitted by unrelated Java apps the way JSESSIONID is).
var strongCookieNames = []string{
	"glide_user_route",
	"glide_node_id_for_js",
	"glide_session_store",
	"glide_user_activity",
}

// strongBodyMarkers are single-hit ServiceNow proofs from the page HTML/JS. A
// bare "g_ck" is deliberately excluded (too short — it can appear in unrelated
// JS); the g_ck CSRF token is still scraped for widget calls via ckTokenRe, and
// these four markers plus the glide_* cookies confirm ServiceNow specifically.
var strongBodyMarkers = []string{
	"window.NOW",
	"GlideForm",
	"sysparm_ck",
	"/scripts/glide",
}

// MatchResponse reports whether a response looks like ServiceNow. setCookies is
// the lowercased, newline-joined Set-Cookie names; body is the response body.
// Used by the passive fingerprint; the active modules gate on AcquireSession
// (obtaining a guest g_ck token), not on these markers.
func MatchResponse(setCookies, body string) (ok bool, signals []string) {
	sc := strings.ToLower(setCookies)
	for _, c := range strongCookieNames {
		if strings.Contains(sc, c) {
			signals = append(signals, "cookie: "+c)
		}
	}
	for _, m := range strongBodyMarkers {
		if strings.Contains(body, m) {
			signals = append(signals, "body marker: "+m)
		}
	}
	return len(signals) > 0, signals
}

// ckTokenRe matches the g_ck CSRF token in page HTML/JS: var g_ck = '...' or
// window.g_ck = "..." or the sysparm_ck hidden input value.
var ckTokenRe = regexp.MustCompile(`(?:g_ck\s*=\s*|["']sysparm_ck["'][^>]*value\s*=\s*|["']ck["']\s*:\s*)["']([A-Za-z0-9+/=_\-]{24,})["']`)

// Session carries the guest session cookies and CSRF token needed to call a
// widget API as an unauthenticated user.
type Session struct {
	Token  string // X-UserToken (g_ck)
	Cookie string // Cookie header value (name=value; name=value)
}

// AcquireSession GETs a Service Portal landing page, scraping the g_ck CSRF token
// and capturing the guest session cookies it sets. ok is false when no token can
// be obtained (the widget POST would then 401). The g_ck token is a CSRF token,
// not an authorization credential — an unauthenticated guest legitimately carries
// one.
func AcquireSession(ctx *httpmsg.HttpRequestResponse, client *http.Requester) (Session, bool) {
	for _, p := range []string{"/", "/sp", "/login.do"} {
		res := saasprobe.GetFollow(ctx, client, p, nil)
		if !res.OK {
			continue
		}
		token := ""
		if m := ckTokenRe.FindStringSubmatch(res.Body); m != nil {
			token = m[1]
		}
		if token == "" {
			continue
		}
		return Session{Token: token, Cookie: cookieHeaderFrom(res)}, true
	}
	// Fallback: the devstudio processor returns the ck token as JSON on all
	// instances, independent of HTML scraping.
	res := saasprobe.GetFollow(ctx, client, "/sn_devstudio_/v1/get_publish_info", nil)
	if res.OK {
		if m := ckTokenRe.FindStringSubmatch(res.Body); m != nil {
			return Session{Token: m[1], Cookie: cookieHeaderFrom(res)}, true
		}
	}
	return Session{}, false
}

// cookieHeaderFrom builds a Cookie header value from a probe result's Set-Cookie
// headers (name=value pairs only, attributes dropped).
func cookieHeaderFrom(res saasprobe.Result) string {
	if res.Header == nil {
		return ""
	}
	var pairs []string
	for _, sc := range res.Header.Values("Set-Cookie") {
		if i := strings.IndexByte(sc, ';'); i >= 0 {
			sc = sc[:i]
		}
		sc = strings.TrimSpace(sc)
		if sc != "" && strings.Contains(sc, "=") {
			pairs = append(pairs, sc)
		}
	}
	return strings.Join(pairs, "; ")
}

// MarkServiceNow records ServiceNow in the tech registry for host. The active
// modules call it after AcquireSession succeeds — obtaining a guest g_ck token IS
// the fail-closed presence gate (a non-ServiceNow host yields no token), so there
// is no separate Confirm step that would re-fetch the same landing pages.
func MarkServiceNow(sc *modkit.ScanContext, host string) {
	if sc == nil || host == "" {
		return
	}
	sc.MarkTech(host, Tag)
	sc.MarkTech(host, "java")
}
