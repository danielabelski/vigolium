package bfla_detection

import (
	"bytes"
	"fmt"
	"math"
	"path"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// adminPathPatterns contains path segments that indicate admin/privileged endpoints.
var adminPathPatterns = []string{
	"/admin",
	"/management",
	"/manager",
	"/dashboard",
	"/console",
	"/api/admin",
	"/api/v1/admin",
	"/users/delete",
	"/users/create",
	"/settings",
	"/config",
	"/system",
	"/internal",
	"/debug",
	"/actuator",
	"/ops",
	"/backoffice",
	"/moderate",
	"/staff",
}

// Module implements the BFLA detection active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new BFLA Detection module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("bfla_detection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests privileged endpoints for broken function-level authorization.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Skip media and JS URLs
	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Check if this looks like an admin/privileged endpoint
	if !isAdminPath(urlx.Path) {
		return nil, nil
	}

	// Health/liveness probes sit under privileged-looking prefixes but are public
	// by design and expose no privileged function — see isBenignProbePath.
	if isBenignProbePath(urlx.Path) {
		return nil, nil
	}

	// Original response must be 2xx (we can only test what currently succeeds)
	if ctx.Response() == nil {
		return nil, nil
	}
	origStatus := ctx.Response().StatusCode()
	if origStatus < 200 || origStatus >= 300 {
		return nil, nil
	}
	// The 2xx gate above already excludes the common vendor blocks that carry a
	// blocking status (403/503/429). This additionally drops a WAF/CDN challenge
	// served AT 200 (Cloudflare managed challenge, Cf-Mitigated, or a challenge-body
	// marker): BFLA deliberately targets admin paths, which carry the strictest,
	// path-scoped WAF rules, so an auth-stripped probe hits the SAME 200 challenge
	// page (the edge ignores the credential) and reads as content-similar — while the
	// random-path catch-all controls dodge the path-scoped rule and can't cancel it.
	// A challenge page is never a genuine privileged baseline, so drop it.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}
	origBody := ctx.Response().Body()
	origBodyLen := len(origBody)

	// An empty (or whitespace-only) "privileged" response carries no privileged
	// content to compare against. When the endpoint's own baseline is a
	// Content-Length: 0 body, every sub-test degenerates into matching nothing
	// against nothing: an auth-stripped or method-switched request that returns the
	// same empty 200 looks identical but proves no function-level bypass. This is
	// the dominant false positive — fronting CDNs, XSRF/login bounces, and JSP
	// `.jspa` action handlers all answer unauthenticated requests with an empty 200
	// (e.g. globex-agile.atlassian.net /secure/ConfigureReport.jspa: empty 200 for
	// both GET and POST). With no privileged content to reproduce, do not test.
	if len(bytes.TrimSpace(origBody)) == 0 {
		return nil, nil
	}

	// Skip static asset / binary responses (images, fonts, media, archives, JS,
	// CSS). These are CDN-served files, not privileged "endpoints": an Akamai /
	// Scene7 image route such as /is/image/globex/System Image returns 200 to
	// everyone by design, and stripping or switching auth trivially yields the same
	// bytes — never an authorization bypass. The admin-path heuristic misfires on
	// these (here "/system" matched inside the "System Image" filename segment),
	// so gate on the response content type, falling back to a binary-body sniff
	// when the Content-Type header is missing or misleading.
	if modkit.IsStaticAssetContentType(ctx.Response().Header("Content-Type")) || looksBinaryBody(origBody) {
		return nil, nil
	}

	// The same reasoning by cache semantics rather than content type: a body the
	// origin publishes as a long-lived, publicly cacheable artifact is served
	// identically to every caller, so it cannot be a privileged function's output
	// however admin-like its path reads. See looksCacheableStatic.
	if looksCacheableStatic(ctx.Response()) {
		return nil, nil
	}

	// Probe the host with a random nonexistent path. If the original "admin"
	// response is just the host's wildcard / SPA shell, every BFLA test will
	// fire because removing auth still returns the same shell. Bail out.
	wildcard, _ := scanCtx.WildcardProbe(ctx, httpClient)
	if wildcard.MatchesBody(origStatus, origBody) {
		return nil, nil
	}

	// Whether the captured request proves anything about authorization at all is
	// one property of one immutable request, so decide it once here rather than
	// letting each sub-test re-derive it: without credentials there is no
	// authenticated baseline, and a successful "unauthenticated" probe only
	// restates that the endpoint is public.
	hasCreds := requestHasCredentials(ctx.Request())

	var results []*output.ResultEvent

	// Test a) Remove Authorization and Cookie headers
	result, err := m.testNoAuth(ctx, httpClient, urlx, origStatus, origBody, origBodyLen, hasCreds, wildcard)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		// Non-fatal, continue to next test
	}
	if result != nil {
		results = append(results, result)
	}

	// Test b) Downgrade role with empty/generic token
	result, err = m.testDowngradedAuth(ctx, httpClient, urlx, origStatus, origBody, origBodyLen, wildcard)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
	}
	if result != nil {
		results = append(results, result)
	}

	// Test c) Method switching on admin paths without auth
	methodResults, err := m.testMethodSwitching(ctx, httpClient, urlx, origStatus, origBody, hasCreds, wildcard)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
	}
	if len(methodResults) > 0 {
		results = append(results, methodResults...)
	}

	return results, nil
}

// testNoAuth removes Authorization and Cookie headers and checks if the endpoint still responds with 2xx.
func (m *Module) testNoAuth(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlx *urlutil.URL,
	origStatus int,
	origBody []byte,
	origBodyLen int,
	hasCreds bool,
	wildcard *modkit.WildcardEntry,
) (*output.ResultEvent, error) {
	// A "missing authorization" bypass is only meaningful when the original
	// request actually carried credentials. If it presented neither an
	// Authorization header nor a Cookie there is nothing to strip — the
	// "unauthenticated" request is byte-for-byte the original, so a 200 simply
	// means the endpoint is public. That is the dominant false positive: a
	// "/debug/", "/internal/" or "/config/" landing page on a CDN that was never
	// authorization-gated. Without an authenticated baseline we cannot distinguish
	// a public page from a real bypass, so require credentials before testing.
	if !hasCreds {
		return nil, nil
	}

	modifiedRaw, err := httpmsg.RemoveHeader(ctx.Request().Raw(), "Authorization")
	if err != nil {
		return nil, err
	}
	modifiedRaw, err = httpmsg.RemoveHeader(modifiedRaw, "Cookie")
	if err != nil {
		return nil, err
	}

	// RemoveHeader produces well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, nil
	}

	respStatus := resp.Response().StatusCode
	respBodyBytes := append([]byte(nil), resp.Body().Bytes()...)
	respBody := resp.FullResponseString()
	// Body-only length: it is compared against origBodyLen (also body-only) and
	// reported as the body length. Using the full response string here would
	// contaminate the length differential with the header block — volatile
	// per-request headers (Set-Cookie session blobs, Date, request-ids) — which
	// systematically inflates the magnitude and skews the similarity band.
	// respBody (the full string) stays for the Response: evidence field only.
	respBodyLen := len(respBodyBytes)

	// Reject responses that match the wildcard shell — those are the same
	// page the host returns for every URL, not a real bypass.
	if wildcard.MatchesBody(respStatus, respBodyBytes) {
		return nil, nil
	}

	// Report if original was 200 AND unauthenticated request is also 200 AND the
	// unauthenticated body is the SAME privileged content (not just a similar
	// length). Requiring content similarity, not only a length band, rejects the
	// common false positive where removing auth yields a 200 login/landing page
	// that merely happens to be a comparable size to the protected page.
	if origStatus == 200 && respStatus == 200 && isBodyLengthSimilar(origBodyLen, respBodyLen) &&
		bodiesContentSimilar(origStatus, origBody, respStatus, respBodyBytes) {
		// Confirm the privileged path differs from how the host answers an
		// unauthenticated request to a random path with this method. A host that
		// serves the same 200 shell (login bounce, empty body) for every path is a
		// catch-all, not a real authorization bypass — the byte-head wildcard guard
		// misses this when a reflected path makes the shell's head bytes differ.
		method, _ := httpmsg.GetMethod(modifiedRaw)
		baseStatus, baseBody, ok := probeMethodBaseline(ctx, httpClient, method)
		if ok && matchesMethodBaseline(respStatus, respBodyBytes, baseStatus, baseBody) {
			return nil, nil
		}
		// Confirm the privileged content reproduces across several fresh
		// unauthenticated requests. Endpoints whose body varies per request
		// (rotating tokens, A/B variants, edge-cache flapping) can cross the
		// similarity threshold once by chance; a real authorization bypass returns
		// the same privileged content every time, a coincidental match does not.
		if !confirmPrivilegedReproduces(ctx, httpClient, modifiedRaw, origStatus, origBody) {
			return nil, nil
		}
		ev := modkit.NewEvidenceCollector()
		ev.Add("original-auth", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))
		return &output.ResultEvent{
			URL:                urlx.String(),
			Matched:            urlx.String(),
			Request:            string(modifiedRaw),
			Response:           respBody,
			AdditionalEvidence: ev.Entries(),
			FuzzingParameter:   "Authorization",
			ExtractedResults: []string{
				fmt.Sprintf("Original status: %d, Unauthenticated status: %d", origStatus, respStatus),
				fmt.Sprintf("Original body length: %d, Unauthenticated body length: %d", origBodyLen, respBodyLen),
			},
			Info: output.Info{
				Name:        "BFLA: Unauthenticated Access to Privileged Endpoint",
				Description: "The privileged endpoint returns a successful response after removing Authorization and Cookie headers, indicating broken function-level authorization.",
			},
		}, nil
	}

	return nil, nil
}

// testDowngradedAuth attempts to send a generic/empty Bearer token.
func (m *Module) testDowngradedAuth(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlx *urlutil.URL,
	origStatus int,
	origBody []byte,
	origBodyLen int,
	wildcard *modkit.WildcardEntry,
) (*output.ResultEvent, error) {
	// Check if there is an Authorization header with a Bearer token
	authHeader, err := httpmsg.GetHeaderValue(ctx.Request().Raw(), "Authorization")
	if err != nil || authHeader == "" {
		return nil, nil
	}

	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return nil, nil
	}

	// Replace with an empty Bearer token
	modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), "Authorization", "Bearer invalid_downgraded_token")
	if err != nil {
		return nil, err
	}

	// AddOrReplaceHeader produces well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, nil
	}

	respStatus := resp.Response().StatusCode
	respBodyBytes := append([]byte(nil), resp.Body().Bytes()...)
	respBody := resp.FullResponseString()
	respBodyLen := len(respBodyBytes) // body-only length (see testNoAuth); respBody is evidence only

	if wildcard.MatchesBody(respStatus, respBodyBytes) {
		return nil, nil
	}

	if origStatus == 200 && respStatus == 200 && isBodyLengthSimilar(origBodyLen, respBodyLen) &&
		bodiesContentSimilar(origStatus, origBody, respStatus, respBodyBytes) {
		// Reject the catch-all case where the host answers identically for a random
		// path with this same method (see testNoAuth for the rationale).
		method, _ := httpmsg.GetMethod(modifiedRaw)
		baseStatus, baseBody, ok := probeMethodBaseline(ctx, httpClient, method)
		if ok && matchesMethodBaseline(respStatus, respBodyBytes, baseStatus, baseBody) {
			return nil, nil
		}
		// Require the privileged content to reproduce across several downgraded
		// requests, rejecting endpoints whose body merely happens to look similar
		// on a single dynamic sample (see testNoAuth for the rationale).
		if !confirmPrivilegedReproduces(ctx, httpClient, modifiedRaw, origStatus, origBody) {
			return nil, nil
		}
		ev := modkit.NewEvidenceCollector()
		ev.Add("original-auth", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))
		return &output.ResultEvent{
			URL:                urlx.String(),
			Matched:            urlx.String(),
			Request:            string(modifiedRaw),
			Response:           respBody,
			AdditionalEvidence: ev.Entries(),
			FuzzingParameter:   "Authorization",
			ExtractedResults: []string{
				fmt.Sprintf("Original status: %d, Downgraded token status: %d", origStatus, respStatus),
				"Token replaced with invalid_downgraded_token",
			},
			Info: output.Info{
				Name:        "BFLA: Downgraded Token Accepted on Privileged Endpoint",
				Description: "The privileged endpoint returns a successful response with an invalid/downgraded Bearer token, indicating broken function-level authorization.",
			},
		}, nil
	}

	return nil, nil
}

// testMethodSwitching tries different HTTP methods on admin paths without auth.
func (m *Module) testMethodSwitching(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlx *urlutil.URL,
	origStatus int,
	origBody []byte,
	hasCreds bool,
	wildcard *modkit.WildcardEntry,
) ([]*output.ResultEvent, error) {
	// Only test method switching if original request is GET
	method, err := httpmsg.GetMethod(ctx.Request().Raw())
	if err != nil || strings.ToUpper(method) != "GET" {
		return nil, nil
	}

	// The baseline is invariant across the three method attempts below, so
	// tokenize it once instead of rebuilding its signature per attempt.
	origSig := modkit.BodySignature(string(origBody))

	var results []*output.ResultEvent
	methodsToTry := []string{"POST", "PUT", "DELETE"}

	for _, tryMethod := range methodsToTry {
		// Switch method and remove auth
		modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), tryMethod)
		if err != nil {
			continue
		}
		modifiedRaw, err = httpmsg.RemoveHeader(modifiedRaw, "Authorization")
		if err != nil {
			continue
		}
		modifiedRaw, err = httpmsg.RemoveHeader(modifiedRaw, "Cookie")
		if err != nil {
			continue
		}

		// SetMethod/RemoveHeader produce well-formed raw, so wrap directly
		// instead of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, err
			}
			continue
		}

		if resp.Response() != nil && resp.Response().StatusCode >= 200 && resp.Response().StatusCode < 300 &&
			!wildcard.MatchesBody(resp.Response().StatusCode, resp.Body().Bytes()) {
			respStatus := resp.Response().StatusCode
			candBody := append([]byte(nil), resp.Body().Bytes()...)
			respBody := resp.FullResponseString()
			resp.Close()

			// A switched-method response with an empty body is not evidence that the
			// privileged function executed. A 2xx with no content is the signature of an
			// edge gateway or action handler swallowing the request — the
			// globex-agile.atlassian.net /secure/ConfigureReport.jspa report returned an
			// empty 200 for POST identical to the GET. Require actual content before
			// flagging a method-switch bypass.
			if len(bytes.TrimSpace(candBody)) == 0 {
				continue
			}

			// When the original GET carried no credentials and the switched method
			// returns the SAME representation that GET already served to everyone, the
			// route simply ignores the method — a static file, a health probe, a CDN
			// object — and nothing about function-level authorization has been shown.
			// Two live false positives had exactly this shape: a cacheable Tableau
			// error page and `<health>ok</health>`, both answering POST with
			// byte-identical content on an endpoint that needed no credentials to
			// begin with. Where the original request DID carry credentials, identical
			// content is the opposite signal — the privileged representation came back
			// unauthenticated — so only the no-credential case is dropped.
			if !hasCreds && sigMatchesBody(origSig, candBody) {
				continue
			}

			// Confirm the privileged endpoint answers differently than the host does
			// for an arbitrary path with this same method. A host that accepts
			// POST/PUT/DELETE everywhere (e.g. an empty Content-Length:0 200 from an
			// edge gateway) returns the same thing for "/", "/includes/" and the
			// admin path alike — a catch-all, not a function-level auth bypass.
			baseStatus, baseBody, ok := probeMethodBaseline(ctx, httpClient, tryMethod)
			if ok && matchesMethodBaseline(respStatus, candBody, baseStatus, baseBody) {
				continue
			}

			// Reproduce control (parity with testNoAuth/testDowngradedAuth): re-issue
			// the switched-method request and require the same privileged content
			// across fresh samples. A per-request-varying body (randomized SSR shell,
			// live dashboard, per-request token) that merely differs from the
			// method-baseline once will not reproduce content-similar, so it is
			// dropped rather than flagged as a function-level auth bypass.
			if !confirmPrivilegedReproduces(ctx, httpClient, modifiedRaw, respStatus, candBody) {
				continue
			}

			ev := modkit.NewEvidenceCollector()
			ev.Add("original-auth", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))
			results = append(results, &output.ResultEvent{
				URL:                urlx.String(),
				Matched:            urlx.String(),
				Request:            string(modifiedRaw),
				Response:           respBody,
				AdditionalEvidence: ev.Entries(),
				FuzzingParameter:   "method",
				ExtractedResults: []string{
					fmt.Sprintf("Method %s accepted without authentication on admin path", tryMethod),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("BFLA: Unauthenticated %s on Privileged Endpoint", tryMethod),
					Description: fmt.Sprintf("The privileged endpoint accepts %s requests without authentication, indicating broken function-level authorization.", tryMethod),
				},
			})
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// probeMethodBaseline sends method to a random, non-existent path on the same
// host with Authorization and Cookie stripped, returning how the host answers an
// unauthenticated request with this method for a path that cannot map to any real
// privileged function. A host (CDN/edge/SPA gateway) that accepts the method for
// every path — returning a uniform 2xx such as an empty Content-Length:0 body or a
// soft login-redirect shell — yields the same answer here as on the "admin" path,
// which lets callers reject that catch-all instead of flagging it as a
// function-level authorization bypass. The synthetic "-vigolium-wp/" marker mirrors
// the wildcard probe so it is unlikely to collide with a real route.
//
// ok is false when the probe could not be issued or produced no response.
func probeMethodBaseline(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	method string,
) (status int, body []byte, ok bool) {
	probePath := "/" + utils.RandomString(12) + "-vigolium-wp/" + utils.RandomString(8)

	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
	if err != nil {
		return 0, nil, false
	}
	if raw, err = httpmsg.SetPath(raw, probePath); err != nil {
		return 0, nil, false
	}
	if raw, err = httpmsg.RemoveHeader(raw, "Authorization"); err != nil {
		return 0, nil, false
	}
	if raw, err = httpmsg.RemoveHeader(raw, "Cookie"); err != nil {
		return 0, nil, false
	}

	// SetMethod/SetPath/RemoveHeader produce well-formed raw, so wrap
	// directly instead of re-parsing on this hot path.
	probeReq := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

	resp, _, err := httpClient.Execute(probeReq, http.Options{NoRedirects: true})
	if err != nil || resp == nil {
		return 0, nil, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, nil, false
	}
	return resp.Response().StatusCode, append([]byte(nil), resp.Body().Bytes()...), true
}

// matchesMethodBaseline reports whether a candidate response is indistinguishable
// from the same-method baseline against a random non-existent path: identical
// status and substantially the same body (two empty bodies count as identical via
// QuickRatio). When true, the host returns a uniform answer for this method
// regardless of path — a catch-all gateway, not a path-specific authorization
// bypass — so the finding must be dropped.
func matchesMethodBaseline(candStatus int, candBody []byte, baseStatus int, baseBody []byte) bool {
	if candStatus != baseStatus {
		return false
	}
	return bodiesContentSimilar(candStatus, candBody, baseStatus, baseBody)
}

// bflaConfirmSamples is how many additional times an auth-stripped or downgraded
// request is re-issued to confirm the privileged content reproduces. A single
// sample is not enough when the endpoint's body varies per request; a real bypass
// returns the same privileged content every time, a page that randomizes does not.
const bflaConfirmSamples = 2

// confirmPrivilegedReproduces re-issues the modified (auth-stripped or downgraded)
// request bflaConfirmSamples more times and reports whether every fresh response
// still returns the same privileged content (same status, content-similar body) as
// the authenticated baseline. It returns false on the first sample that fails to
// reproduce — a transport error, a status change, or a body that no longer matches
// the privileged content — so a coincidental one-shot similarity to a dynamic page
// is rejected before a finding is raised.
func confirmPrivilegedReproduces(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	modifiedRaw []byte,
	origStatus int,
	origBody []byte,
) bool {
	for i := 0; i < bflaConfirmSamples; i++ {
		// modifiedRaw is already well-formed, so wrap directly instead of
		// re-parsing on this hot path.
		req := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		// NoClustering is essential: the requester caches identical requests for a
		// short TTL, so without it every re-sample would return the first probe's
		// cached body and a flapping endpoint would look perfectly reproducible.
		resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
		if err != nil || resp == nil {
			return false
		}
		if resp.Response() == nil {
			resp.Close()
			return false
		}
		status := resp.Response().StatusCode
		body := append([]byte(nil), resp.Body().Bytes()...)
		resp.Close()

		if status != origStatus || !bodiesContentSimilar(origStatus, origBody, status, body) {
			return false
		}
	}
	return true
}

// isAdminPath checks if the path matches known admin/privileged patterns
// (case-insensitive), anchored so a pattern cannot match the leading word of a
// longer identifier — see pathPatternMatches.
func isAdminPath(path string) bool {
	lower := strings.ToLower(path)
	for _, pattern := range adminPathPatterns {
		if pathPatternMatches(path, lower, pattern) {
			return true
		}
	}
	return false
}

// pathPatternMatches reports whether pattern (always "/word…", lowercase) occurs
// in path with a clean right-hand boundary. lower must be strings.ToLower(path);
// the caller supplies it so the lowercase copy is made once per request rather
// than once per pattern, while boundaryTerminates still sees the original case.
// Every pattern starts with "/", so the left edge is already a segment boundary
// and only the trailing edge needs checking.
func pathPatternMatches(path, lower, pattern string) bool {
	for from := 0; from <= len(lower)-len(pattern); {
		idx := strings.Index(lower[from:], pattern)
		if idx < 0 {
			return false
		}
		start := from + idx
		if boundaryTerminates(path, start+len(pattern)) {
			return true
		}
		from = start + 1
	}
	return false
}

// boundaryTerminates reports whether the byte at end closes the matched pattern
// as its own word: end-of-path, a separator, or a lowercase continuation (so
// "/admin" still matches "/administration"). Anything else — an uppercase
// letter, a digit, a space — means the pattern was only the first
// camelCase/compound word of a longer identifier:
// "internalServerError.var" is a static error page's filename, not the
// "/internal" admin tree, and "System Image" is an image filename, not
// "/system".
//
// The unbounded substring match was a live false positive: Tableau's cacheable
// /vizportalclient/internalServerError.var was classified as a privileged
// endpoint, and because a static file answers every method with the same bytes,
// the method-switch test then reported a High authorization bypass on it.
func boundaryTerminates(path string, end int) bool {
	if end >= len(path) {
		return true
	}
	c := path[end]
	return strings.IndexByte("/-_.?&=", c) >= 0 || (c >= 'a' && c <= 'z')
}

// benignProbeNames are final path-segment names for endpoints whose entire
// purpose is to answer unauthenticated requests: health, liveness and readiness
// probes. They frequently sit under a privileged-looking prefix
// ("/actuator/health", "/internal/ping") yet expose no privileged function, and
// they return one fixed body for every method — so every BFLA sub-test passes
// trivially. Live false positive: POST //actuator/healthcheck answering
// `<health>ok</health>` was reported as a High authorization bypass.
var benignProbeNames = map[string]struct{}{
	"alive": {}, "health": {}, "health-check": {}, "healthcheck": {},
	"healthchecks": {}, "healthz": {}, "heartbeat": {}, "liveness": {},
	"livez": {}, "ping": {}, "readiness": {}, "ready": {}, "readyz": {},
}

// isBenignProbePath reports whether the path's last segment names a
// health/liveness probe (see benignProbeNames). A trailing file extension is
// stripped so "/health.json" and "/healthz.txt" match too — but only when the
// dot is not the leading character, so a dotfile keeps its whole name.
func isBenignProbePath(p string) bool {
	last := path.Base(strings.Trim(p, "/"))
	if ext := path.Ext(last); len(ext) < len(last) {
		last = strings.TrimSuffix(last, ext)
	}
	_, ok := benignProbeNames[strings.ToLower(last)]
	return ok
}

// requestHasCredentials reports whether a request carried an Authorization
// header or a Cookie. Without one there is no authenticated baseline, so a
// successful "unauthenticated" probe only restates that the endpoint is public.
// It reads through HttpRequest's memoized header parse rather than re-scanning
// the raw bytes on every call.
func requestHasCredentials(req *httpmsg.HttpRequest) bool {
	return strings.TrimSpace(req.Header("Authorization")) != "" ||
		strings.TrimSpace(req.Header("Cookie")) != ""
}

// staticCacheMinAge is the Cache-Control max-age (one hour) at or above which a
// 2xx response is treated as a shipped static resource rather than a live
// privileged function. Privileged endpoints are served no-store/private or with
// a short TTL; files shipped by the origin carry hours to years.
const staticCacheMinAge = 3600

// looksCacheableStatic reports whether a response is a stored static artifact:
// publicly cacheable for a long TTL, carrying a validator, and setting no
// session cookie. Such a body is identical for every caller and every method, so
// it can never evidence a function-level authorization bypass. The
// Content-Type-based static-asset check cannot see these — Tableau's
// internalServerError.var is served as text/html with
// `Cache-Control: max-age=31536000`, `Expires`, `Accept-Ranges: bytes` and
// validators — but the cache headers can.
func looksCacheableStatic(resp *httpmsg.HttpResponse) bool {
	if resp == nil {
		return false
	}
	cc := strings.ToLower(resp.Header("Cache-Control"))
	if cc == "" ||
		strings.Contains(cc, "no-store") ||
		strings.Contains(cc, "no-cache") ||
		strings.Contains(cc, "private") {
		return false
	}
	if strings.TrimSpace(resp.Header("Set-Cookie")) != "" {
		return false
	}
	if age, ok := infra.CacheMaxAge(cc); !ok || age < staticCacheMinAge {
		return false
	}
	// A validator confirms the body is an artifact the origin can revalidate,
	// not a response rendered per request.
	return strings.TrimSpace(resp.Header("ETag")) != "" ||
		strings.TrimSpace(resp.Header("Last-Modified")) != ""
}

// bflaContentSimilarityMin is the minimum normalized token similarity between the
// authenticated and the auth-stripped response bodies for them to count as "the
// same privileged content". High enough to separate the real protected page from
// a login/landing/error page, low enough to tolerate per-request dynamic bits
// (usernames, CSRF tokens, timestamps — which NewResponseSignature already
// collapses) on a genuine bypass.
const bflaContentSimilarityMin = 0.8

// bodiesContentSimilar reports whether two response bodies are substantially the
// same content by normalized token similarity (dynamic hex/digit runs collapsed).
func bodiesContentSimilar(_ int, bodyA []byte, _ int, bodyB []byte) bool {
	return sigMatchesBody(modkit.BodySignature(string(bodyA)), bodyB)
}

// sigMatchesBody is the signature-reuse form of bodiesContentSimilar, for
// callers comparing one stable baseline against several candidates: it
// tokenizes only the candidate. BodySignature is used rather than
// NewResponseSignature because QuickRatio reads only the token counts — the
// status code and the SHA-256 of the body would be computed and never looked at.
func sigMatchesBody(sig modkit.ResponseSignature, body []byte) bool {
	return modkit.QuickRatio(sig, modkit.BodySignature(string(body))) >= bflaContentSimilarityMin
}

// isBodyLengthSimilar returns true if the two body lengths are within 50% of each other.
func isBodyLengthSimilar(origLen, newLen int) bool {
	if origLen == 0 && newLen == 0 {
		return true
	}
	if origLen == 0 || newLen == 0 {
		return false
	}
	ratio := math.Abs(float64(origLen-newLen)) / float64(origLen)
	return ratio <= 0.5
}

// looksBinaryBody sniffs a response body for binary content when the Content-Type
// is missing or misleading (a CDN mislabeling an image as text/html, say). A NUL
// byte is decisive; otherwise a high ratio of control bytes (excluding
// tab/newline/CR) in the leading window marks it binary. High bytes (0x80+) are
// left uncounted so valid UTF-8 text is never misread as binary.
func looksBinaryBody(body []byte) bool {
	n := len(body)
	if n == 0 {
		return false
	}
	if n > 2048 {
		n = 2048
	}
	nonText := 0
	for i := 0; i < n; i++ {
		c := body[i]
		switch {
		case c == 0:
			return true
		case c == 0x09 || c == 0x0a || c == 0x0d:
			// tab / newline / carriage-return — text
		case c < 0x20 || c == 0x7f:
			nonText++
		}
	}
	return float64(nonText)/float64(n) > 0.10
}
