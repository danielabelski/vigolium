package security_headers_missing

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "security-headers-missing"
	ModuleName  = "Security Headers Missing"
	ModuleShort = "Detects missing/weak HTTP security headers and cacheable sensitive responses"
)

var (
	ModuleDesc = `**What it means:** An HTML response lacks X-Content-Type-Options, CSP, HTTPS HSTS, a safe explicit Referrer-Policy, or session-safe cache directives. Contextual analyzers handle clickjacking and Permissions-Policy. This is an observation.

**How it's exploited:** These gaps can amplify XSS, MIME sniffing, SSL stripping, referrer leakage, or caching of session content.

**Fix:** Send the recommended security headers (HSTS, CSP, X-Content-Type-Options nosniff), a strict Referrer-Policy, and Cache-Control no-store on sensitive HTTPS pages.`

	ModuleConfirmation = "Confirmed when an HTTP response lacks recommended security headers, uses a weak Referrer-Policy, or serves cacheable sensitive content"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "misconfiguration", "light"}
)
