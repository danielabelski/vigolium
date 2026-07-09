package aspnet_identity_probe

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
	// jsonBody marks a probe whose genuine hit is a structured JSON document (an
	// OAuth/OIDC token error, a JWKS key set, an ASP.NET Core Identity API reply) —
	// never an HTML *document*. It enables the content-type discipline that survives
	// the catch-all/echo body-truncation FP: a gzip + bogus Content-Length:0 quirk
	// can leave the scanner with only a partial body tail (no <!DOCTYPE/<html>), so
	// body anti-markers ("<html") and shell-similarity guards are defeated — but the
	// Content-Type header is intact. A reflecting/catch-all host that answers ANY
	// path with its themed text/html shell then forges a match on a weak JSON marker
	// ("email", `"errors":{`) sitting in that tail. Rejecting an HTML document for a
	// probe whose real reply is JSON is the decisive, zero-false-negative guard.
	// Probes whose genuine hit legitimately IS an HTML page (a scaffolded Identity
	// UI, the authorize error/login page) leave this false and rely on the decoy
	// catch-all disproof instead.
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
	// NOTE: the generic OIDC discovery document at /.well-known/openid-configuration
	// is intentionally NOT probed here. It is public by design (OpenID Connect
	// Discovery 1.0) and not ASP.NET-specific, and it is already reported once by
	// probeOIDCDiscovery (a single Low finding with the extracted endpoint/scope/
	// grant metadata). Listing it here too would double-report the same URL.

	// IdentityServer / Duende endpoints
	{
		path:        "/connect/token",
		name:        "Token Endpoint",
		markers:     []string{"invalid_client", "invalid_grant", "unsupported_grant_type"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "OAuth2/OIDC token endpoint accessible, may be susceptible to brute force or credential stuffing without rate limiting",
		jsonBody:    true, // token endpoint errors are JSON, never an HTML document
	},
	{
		path:        "/connect/authorize",
		name:        "Authorization Endpoint",
		markers:     []string{"client_id", "redirect_uri", "response_type"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "OAuth2/OIDC authorization endpoint detected, confirming IdentityServer/Duende deployment",
	},
	{
		path:        "/.well-known/openid-configuration/jwks",
		name:        "JWKS Endpoint",
		markers:     []string{"\"kty\"", "\"kid\"", "\"n\":", "\"e\":"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Low,
		desc:        "JSON Web Key Set endpoint exposed, revealing public signing keys used for token validation",
		jsonBody:    true, // JWKS is a JSON key set, never an HTML document
	},
	// Scaffolded ASP.NET Identity UI
	{
		path:        "/Identity/Account/Register",
		name:        "Identity Register (Scaffolded)",
		markers:     []string{"__RequestVerificationToken", "ConfirmPassword"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "ASP.NET Identity registration page publicly accessible, potentially allowing unauthorized account creation",
	},
	{
		path:        "/Identity/Account/Login",
		name:        "Identity Login (Scaffolded)",
		markers:     []string{"__RequestVerificationToken", "RememberMe"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "ASP.NET Identity scaffolded login page detected, confirming Identity UI deployment",
	},
	{
		path:        "/Identity/Account/ForgotPassword",
		name:        "Identity Password Reset",
		markers:     []string{"__RequestVerificationToken", "ForgotPassword"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Low,
		desc:        "ASP.NET Identity password reset page exposed, may enable email enumeration",
	},
	// MVC-style Identity endpoints
	{
		path:        "/Account/Register",
		name:        "MVC Register",
		markers:     []string{"__RequestVerificationToken", "ConfirmPassword"},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "ASP.NET MVC registration endpoint publicly accessible",
	},
	// API-based Identity (ASP.NET Core 8+ Identity API endpoints)
	{
		path:        "/register",
		name:        "Identity API Register",
		markers:     []string{"DuplicateUserName", "PasswordTooShort", "\"errors\":{", "InvalidEmail"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE"},
		sev:         severity.Medium,
		desc:        "ASP.NET Core Identity API registration endpoint accessible, may allow unauthorized account creation via API",
		jsonBody:    true, // Identity API validation errors are JSON, never an HTML document
	},
	{
		path:        "/manage/info",
		name:        "Identity API Manage Info",
		markers:     []string{"email", "isEmailConfirmed"},
		antiMarkers: []string{"404", "Not Found", "<html", "<!DOCTYPE", "401"},
		sev:         severity.High,
		desc:        "ASP.NET Core Identity management API accessible without proper authentication",
		jsonBody:    true, // manage/info returns a JSON account object, never an HTML document
	},
}
