package oauth_misconfiguration

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/open_redirect"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// oauthPathPatterns contains path segments indicating OAuth/OIDC endpoints.
var oauthPathPatterns = []string{
	"/authorize",
	"/oauth",
	"/auth/callback",
	"/oidc",
	"/token",
	"/login/oauth",
}

// oauthParamNames contains query parameter names associated with OAuth flows.
var oauthParamNames = []string{
	"client_id",
	"redirect_uri",
	"response_type",
	"scope",
	"state",
}

// Module implements the OAuth/OIDC misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new OAuth/OIDC Misconfiguration module.
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
		ds: dedup.LazyDiskSet("oauth_misconfiguration"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests OAuth/OIDC endpoints for common misconfigurations.
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

	// Detect if this is an OAuth endpoint
	if !isOAuthEndpoint(urlx.Path, ctx.Request().Raw()) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Test a) redirect_uri manipulation
	redirectResults, err := m.testRedirectURIManipulation(ctx, httpClient, urlx)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
	}
	if len(redirectResults) > 0 {
		results = append(results, redirectResults...)
	}

	// Test b) Missing state parameter
	result, err := m.testMissingState(ctx, urlx)
	if err == nil && result != nil {
		results = append(results, result)
	}

	// Test c) response_type downgrade
	result, err = m.testResponseTypeDowngrade(ctx, httpClient, urlx)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
	}
	if result != nil {
		results = append(results, result)
	}

	return results, nil
}

// testRedirectURIManipulation tests if the OAuth endpoint accepts manipulated redirect_uri values.
func (m *Module) testRedirectURIManipulation(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlx *urlutil.URL,
) ([]*output.ResultEvent, error) {
	rawReq := ctx.Request().Raw()

	// Check if redirect_uri is present
	hasRedirectURI, err := httpmsg.HasURLParameter(rawReq, "redirect_uri")
	if err != nil || !hasRedirectURI {
		return nil, nil
	}

	origRedirectURI, err := httpmsg.GetURLParameter(rawReq, "redirect_uri")
	if err != nil || origRedirectURI == "" {
		return nil, nil
	}

	// Extract the legitimate domain from the original redirect_uri for subdomain confusion
	var legitimateDomain string
	if idx := strings.Index(origRedirectURI, "://"); idx != -1 {
		rest := origRedirectURI[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
			legitimateDomain = rest[:slashIdx]
		} else {
			legitimateDomain = rest
		}
	}

	// Payloads to test
	payloads := []struct {
		name  string
		value string
	}{
		{"Direct replacement", "https://evil.example.com/callback"},
		{"Subdomain confusion", fmt.Sprintf("https://evil.example.com@%s/callback", legitimateDomain)},
		{"Path traversal", origRedirectURI + "/../evil.example.com"},
	}

	var results []*output.ResultEvent

	for _, payload := range payloads {
		// Get current params and replace redirect_uri
		params, err := httpmsg.GetURLParametersMap(rawReq)
		if err != nil {
			continue
		}
		params["redirect_uri"] = payload.value

		modifiedRaw, err := httpmsg.SetURLParametersMap(rawReq, params)
		if err != nil {
			continue
		}

		// modifiedRaw is internally built (well-formed), so wrap directly
		// instead of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, err
			}
			continue
		}

		if resp.Response() == nil {
			resp.Close()
			continue
		}

		// Check if the server redirects to the evil URI
		statusCode := resp.Response().StatusCode
		location := resp.Response().Header.Get("Location")

		if statusCode == 302 || statusCode == 301 || statusCode == 303 || statusCode == 307 {
			if redirectsToHost(location, "evil.example.com") {
				// Strict drop-on-fail: confirm the server redirects to an
				// ATTACKER-CHOSEN host, not a coincidental/hardcoded string. A fresh
				// random domain (via the same technique) must appear in Location every
				// round. Fails open only on an inconclusive probe error.
				if !m.confirmRedirectReflection(ctx, httpClient, rawReq, payload.value) {
					resp.Close()
					continue
				}
				respBody := resp.FullResponseString()
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Matched:          urlx.String(),
					Request:          string(modifiedRaw),
					Response:         respBody,
					FuzzingParameter: "redirect_uri",
					ExtractedResults: []string{
						fmt.Sprintf("Technique: %s", payload.name),
						fmt.Sprintf("Injected redirect_uri: %s", payload.value),
						fmt.Sprintf("Location header: %s", location),
					},
					Info: output.Info{
						Name:        fmt.Sprintf("OAuth Open Redirect: %s", payload.name),
						Description: fmt.Sprintf("The OAuth endpoint accepted a manipulated redirect_uri (%s) and redirected to an attacker-controlled domain, enabling authorization code/token theft.", payload.name),
					},
				})
				resp.Close()
				return results, nil
			}
		}
		resp.Close()
	}

	return results, nil
}

// testMissingState checks if an OAuth request is missing the state parameter (CSRF protection).
func (m *Module) testMissingState(
	ctx *httpmsg.HttpRequestResponse,
	urlx *urlutil.URL,
) (*output.ResultEvent, error) {
	rawReq := ctx.Request().Raw()

	// Check if this has OAuth params but no state
	hasState, err := httpmsg.HasURLParameter(rawReq, "state")
	if err != nil {
		return nil, err
	}
	if hasState {
		return nil, nil
	}

	// Verify it actually has other OAuth params (client_id or response_type)
	hasClientID, _ := httpmsg.HasURLParameter(rawReq, "client_id")
	hasResponseType, _ := httpmsg.HasURLParameter(rawReq, "response_type")

	if !hasClientID && !hasResponseType {
		return nil, nil
	}

	return &output.ResultEvent{
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          string(rawReq),
		FuzzingParameter: "state",
		ExtractedResults: []string{
			"OAuth request missing state parameter",
			"CSRF protection absent in authorization flow",
		},
		Info: output.Info{
			Name:        "OAuth Missing State Parameter (CSRF)",
			Description: "The OAuth authorization request does not include a state parameter, making the flow vulnerable to CSRF attacks. An attacker can forge authorization requests to link their account to a victim's session.",
			Severity:    severity.Medium,
		},
	}, nil
}

// testResponseTypeDowngrade tests if the OAuth endpoint accepts a downgrade from code to token (implicit flow).
func (m *Module) testResponseTypeDowngrade(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlx *urlutil.URL,
) (*output.ResultEvent, error) {
	rawReq := ctx.Request().Raw()

	// Check if response_type=code is present
	responseType, err := httpmsg.GetURLParameter(rawReq, "response_type")
	if err != nil || responseType != "code" {
		return nil, nil
	}

	// Replace response_type with token
	params, err := httpmsg.GetURLParametersMap(rawReq)
	if err != nil {
		return nil, err
	}
	params["response_type"] = "token"

	modifiedRaw, err := httpmsg.SetURLParametersMap(rawReq, params)
	if err != nil {
		return nil, err
	}

	// modifiedRaw is internally built (well-formed), so wrap directly instead
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

	statusCode := resp.Response().StatusCode
	respBody := resp.FullResponseString()
	bodyLower := strings.ToLower(respBody)

	// If the server accepts (200 or 302 without error), report
	if (statusCode == 200 || statusCode == 302 || statusCode == 301 || statusCode == 303 || statusCode == 307) &&
		!strings.Contains(bodyLower, "unsupported_response_type") &&
		!strings.Contains(bodyLower, "invalid_request") &&
		!strings.Contains(bodyLower, "error") {
		// Strict drop-on-fail: a "token accepted" signal is only meaningful if the
		// endpoint actually validates response_type. Confirm an obviously invalid
		// response_type is REJECTED; if it is accepted too, the endpoint ignores
		// the parameter and this is not a genuine implicit-flow downgrade.
		if !m.responseTypeRejectsInvalid(ctx, httpClient, rawReq) {
			return nil, nil
		}
		return &output.ResultEvent{
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(modifiedRaw),
			Response:         respBody,
			FuzzingParameter: "response_type",
			ExtractedResults: []string{
				"response_type changed from code to token",
				fmt.Sprintf("Server responded with status %d", statusCode),
			},
			Info: output.Info{
				Name:        "OAuth Implicit Flow Enabled via response_type Downgrade",
				Description: "The OAuth endpoint accepts response_type=token when the original flow uses response_type=code. This enables the less secure implicit flow, exposing access tokens in URL fragments.",
			},
		}, nil
	}

	return nil, nil
}

// confirmRedirectReflection confirms the OAuth endpoint redirects to an
// attacker-CHOSEN host by re-running the same redirect_uri technique with a fresh
// random domain each round and requiring a 3xx whose Location carries that fresh
// domain. Returns true to keep the finding (confirmed, or an inconclusive probe
// error), false to drop a clean non-reflection.
func (m *Module) confirmRedirectReflection(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	rawReq []byte,
	payloadValue string,
) bool {
	confirmed, err := modkit.ConfirmReflection(2, func(canary string) (bool, error) {
		freshHost := "vgo" + canary + ".example.com"
		value := strings.ReplaceAll(payloadValue, "evil.example.com", freshHost)
		params, e := httpmsg.GetURLParametersMap(rawReq)
		if e != nil {
			return false, e
		}
		params["redirect_uri"] = value
		raw, e := httpmsg.SetURLParametersMap(rawReq, params)
		if e != nil {
			return false, e
		}
		// raw is internally built (well-formed), so wrap directly instead of
		// re-parsing on this hot path.
		req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
		resp, _, e := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
		if e != nil {
			return false, e
		}
		defer resp.Close()
		if resp.Response() == nil {
			return false, nil
		}
		st := resp.Response().StatusCode
		loc := resp.Response().Header.Get("Location")
		return st >= 300 && st < 400 && redirectsToHost(loc, freshHost), nil
	})
	return err != nil || confirmed
}

// redirectsToHost reports whether a redirect target (Location value) actually
// points AT host — i.e. host is the AUTHORITY of the redirect, covering the
// https://, //, /\, and userinfo-prefixed forms via the shared open-redirect
// matcher. It deliberately rejects a host that merely appears inside another
// URL's query parameter (a redirect_uri=/continue= echo whose real destination is
// the trusted IdP): that is the recurring OAuth-login false positive where the
// endpoint reflects the manipulated redirect_uri back into the Location but still
// 302s to the SSO, not to the attacker. A bare strings.Contains matched that echo
// (and a fresh canary echoes identically, so even the confirmation passed);
// requiring authority position is the fix.
func redirectsToHost(location, host string) bool {
	if location == "" || host == "" {
		return false
	}
	return open_redirect.DomainRedirectRegex(host).MatchString(location)
}

// responseTypeRejectsInvalid reports whether the endpoint REJECTS an obviously
// invalid response_type value — proving it actually validates the parameter. If
// the invalid value is accepted under the same criteria as the token downgrade,
// the endpoint ignores response_type and the downgrade is not real. Fails OPEN
// (returns true) on an inconclusive probe error.
func (m *Module) responseTypeRejectsInvalid(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	rawReq []byte,
) bool {
	params, err := httpmsg.GetURLParametersMap(rawReq)
	if err != nil {
		return true
	}
	params["response_type"] = "vigolium_invalid_rt"
	raw, err := httpmsg.SetURLParametersMap(rawReq, params)
	if err != nil {
		return true
	}
	// raw is internally built (well-formed), so wrap directly instead of
	// re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return true
	}
	defer resp.Close()
	if resp.Response() == nil {
		return true
	}
	st := resp.Response().StatusCode
	bodyLower := strings.ToLower(resp.FullResponseString())
	accepted := (st == 200 || st == 301 || st == 302 || st == 303 || st == 307) &&
		!strings.Contains(bodyLower, "unsupported_response_type") &&
		!strings.Contains(bodyLower, "invalid_request") &&
		!strings.Contains(bodyLower, "error")
	return !accepted
}

// isOAuthEndpoint checks if the request is for an OAuth/OIDC endpoint based on path and query parameters.
func isOAuthEndpoint(path string, rawReq []byte) bool {
	pathLower := strings.ToLower(path)

	// Check path patterns
	for _, pattern := range oauthPathPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}

	// Check if request has OAuth-related query parameters
	matchCount := 0
	for _, param := range oauthParamNames {
		has, err := httpmsg.HasURLParameter(rawReq, param)
		if err == nil && has {
			matchCount++
		}
	}
	// If at least 2 OAuth params are present, treat as OAuth endpoint
	return matchCount >= 2
}
