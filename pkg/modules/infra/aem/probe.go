// Package aem holds shared detection, probing, and dispatcher-bypass helpers used
// by the aem_* scanner module family (Adobe Experience Manager / Sling / CRX).
//
// It centralizes three things every AEM module needs:
//
//   - Probe helpers (Get/Post) that rebuild the observed request against an
//     arbitrary AEM servlet path with the response cache bypassed.
//   - AEM identification (MatchResponse) and a fail-closed presence gate
//     (ConfirmAEM) so the family only runs against a target that really is AEM.
//   - Dispatcher-bypass path variants (the ;%0a…a.css / .css / /content/..;/ /
//     /// / matrix-parameter tricks) shared by the info-disclosure and bypass
//     modules, so no module re-implements them.
package aem

import (
	nethttp "net/http"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
)

// ProbeResult is the outcome of a single AEM probe request. OK is false on any
// build/transport error, a missing response, OR a WAF/CDN edge challenge — see
// do() — so every caller's existing `if !res.OK` check both fails open on a flaky
// probe and drops a block page without a separate guard.
type ProbeResult struct {
	Status      int
	Body        string
	ContentType string
	Header      nethttp.Header
	OK          bool
}

// Get issues a fresh GET to path on the observed host, reusing the observed
// request's headers/service. extraHeaders (name→value, may be nil) override any
// existing header. Redirects are not followed (a 30x to a login page is not an
// exposure) and the response cache is bypassed so a re-confirmation probe is
// never aliased to a cached entry.
func Get(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string, extraHeaders map[string]string) ProbeResult {
	return do(ctx, client, "GET", path, "", extraHeaders)
}

// Post issues a fresh POST with the given body. Callers that send a form body
// must pass a Content-Type via extraHeaders.
func Post(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path, body string, extraHeaders map[string]string) ProbeResult {
	return do(ctx, client, "POST", path, body, extraHeaders)
}

// Options issues an OPTIONS request — used to read the advertised Allow methods
// for a path without performing any state-changing request.
func Options(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string, extraHeaders map[string]string) ProbeResult {
	return do(ctx, client, "OPTIONS", path, "", extraHeaders)
}

func do(ctx *httpmsg.HttpRequestResponse, client *http.Requester, method, path, body string, extraHeaders map[string]string) ProbeResult {
	if ctx == nil || ctx.Request() == nil || client == nil {
		return ProbeResult{}
	}

	raw := ctx.Request().Raw()
	var err error
	if raw, err = httpmsg.SetMethod(raw, method); err != nil {
		return ProbeResult{}
	}
	if raw, err = httpmsg.SetPath(raw, path); err != nil {
		return ProbeResult{}
	}
	for name, value := range extraHeaders {
		if raw, err = httpmsg.AddOrReplaceHeader(raw, name, value); err != nil {
			return ProbeResult{}
		}
	}
	// Always normalize the body (empty for a bodyless GET) so a probe derived from
	// an observed POST does not inherit that POST's body on a GET request line.
	if raw, err = httpmsg.SetBodyString(raw, body); err != nil {
		return ProbeResult{}
	}

	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return ProbeResult{}
	}
	defer resp.Close()

	r := resp.Response()
	if r == nil {
		return ProbeResult{}
	}
	// Drop WAF/CDN edge challenges and rate-limit interstitials (including a
	// 200-status challenge body) so a block page can never satisfy a content
	// marker — reported as OK:false so every caller's `!res.OK` check covers it and
	// no site needs a separate guard. Validate() is the challenge/rate-limit subset
	// of IsBlockedResponse that deliberately EXCLUDES a bare application 401/403,
	// because callers reason about those statuses (IsProxyBlockedStatus drives the
	// dispatcher-bypass fallback).
	if infra.GetBlockDetectionValidator().Validate(resp) != nil {
		return ProbeResult{}
	}
	return ProbeResult{
		Status:      r.StatusCode,
		Body:        resp.BodyString(),
		ContentType: r.Header.Get("Content-Type"),
		Header:      r.Header,
		OK:          true,
	}
}
