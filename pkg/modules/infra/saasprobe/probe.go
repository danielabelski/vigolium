// Package saasprobe provides a shared, low-level probe helper for the SaaS
// data-exposure module families (Salesforce Aura, ServiceNow Service Portal
// widgets, Microsoft Power Pages / Dataverse). All three families gate on a
// vendor-specific presence check and then send a handful of crafted requests to
// a well-known API surface; the request plumbing is identical, so it lives here
// once instead of being re-implemented per family.
//
// A probe rebuilds the observed request against an arbitrary method/path/body
// (headers overridable), never follows redirects by default (a 30x to a login
// page is not an exposure), and always bypasses the response cache so a
// re-confirmation round is a genuinely independent network observation rather
// than an aliased cached entry. WAF/CDN edge challenges are dropped (reported as
// OK:false) so a block page can never satisfy a content marker.
package saasprobe

import (
	nethttp "net/http"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
)

// Result is the outcome of a single probe request. OK is false on any
// build/transport error, a missing response, OR a WAF/CDN edge challenge — so
// every caller's `if !res.OK` check both fails open on a flaky probe and drops a
// block page without a separate guard.
type Result struct {
	Status int
	Body   string
	Header nethttp.Header
	OK     bool
}

// Get issues a fresh GET to path on the observed host, reusing the observed
// request's headers/service. extraHeaders (name→value, may be nil) override any
// existing header. Redirects are not followed and the response cache is bypassed.
func Get(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string, extraHeaders map[string]string) Result {
	return do(ctx, client, "GET", path, "", extraHeaders, false)
}

// GetFollow is Get but follows redirects — used when harvesting a token/context
// from a landing page that 30x-redirects (e.g. a ServiceNow root that bounces to
// /login.do, or a Salesforce community root to /s/).
func GetFollow(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string, extraHeaders map[string]string) Result {
	return do(ctx, client, "GET", path, "", extraHeaders, true)
}

// Post issues a fresh POST with the given body. Callers that send a form or JSON
// body must pass the matching Content-Type via extraHeaders.
func Post(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path, body string, extraHeaders map[string]string) Result {
	return do(ctx, client, "POST", path, body, extraHeaders, false)
}

// do is the general probe primitive behind Get/GetFollow/Post. follow controls
// redirect handling; every other guard (no clustering, block-page drop, body
// normalization) is always on.
func do(ctx *httpmsg.HttpRequestResponse, client *http.Requester, method, path, body string, extraHeaders map[string]string, follow bool) Result {
	if ctx == nil || ctx.Request() == nil || client == nil {
		return Result{}
	}

	raw := ctx.Request().Raw()
	var err error
	if raw, err = httpmsg.SetMethod(raw, method); err != nil {
		return Result{}
	}
	if raw, err = httpmsg.SetPath(raw, path); err != nil {
		return Result{}
	}
	for name, value := range extraHeaders {
		if raw, err = httpmsg.AddOrReplaceHeader(raw, name, value); err != nil {
			return Result{}
		}
	}
	// Always normalize the body (empty for a bodyless GET) so a probe derived from
	// an observed POST does not inherit that POST's body on a GET request line.
	if raw, err = httpmsg.SetBodyString(raw, body); err != nil {
		return Result{}
	}

	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(req, http.Options{NoRedirects: !follow, NoClustering: true})
	if err != nil {
		return Result{}
	}
	defer resp.Close()

	r := resp.Response()
	if r == nil {
		return Result{}
	}
	// Drop WAF/CDN edge challenges and rate-limit interstitials (including a
	// 200-status challenge body) so a block page can never satisfy a content
	// marker. Validate() deliberately EXCLUDES a bare application 401/403 because
	// these families reason about those statuses (a 401 from a ServiceNow widget is
	// a token failure, a 403 from a Dataverse table is a permission signal).
	if infra.GetBlockDetectionValidator().Validate(resp) != nil {
		return Result{}
	}
	return Result{
		Status: r.StatusCode,
		Body:   resp.BodyString(),
		Header: r.Header,
		OK:     true,
	}
}

// ResponseCookieNames returns the lowercased, newline-joined Set-Cookie names of
// resp, suitable for a substring name test (e.g. `strings.Contains(names,
// "glide_user_route")`) in a family's MatchResponse. Shared by the passive
// *_fingerprint modules so the extraction lives in one place.
func ResponseCookieNames(resp *httpmsg.HttpResponse) string {
	if resp == nil {
		return ""
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return ""
	}
	var b strings.Builder
	for _, c := range cookies {
		b.WriteString(strings.ToLower(c.Name))
		b.WriteByte('\n')
	}
	return b.String()
}
