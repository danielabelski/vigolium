package cookie_security_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cookie-security-detect"
	ModuleName  = "Cookie Security Detect"
	ModuleShort = "Detects insecure cookie attributes in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** A structurally parsed Set-Cookie header omits a hardening attribute. Likely session cookies missing Secure or HttpOnly become candidates; preference cookies, missing SameSite alone, and browser-rejected prefix combinations remain observations.

**How it's exploited:** Without HttpOnly, XSS-injected JavaScript can steal the token and hijack the account. Without Secure, the cookie travels over plain HTTP for a network attacker to capture. Without SameSite, the browser attaches it to cross-site requests, enabling CSRF.

**Fix:** Set Secure, HttpOnly, and an explicit SameSite (Lax or Strict) on all session and sensitive cookies, scoped with a restrictive Path and Domain.`

	ModuleConfirmation = "Candidate only for likely session cookies missing material transport/script protections; other cookie posture is retained as observation"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"session", "misconfiguration", "header-security", "light"}
)
