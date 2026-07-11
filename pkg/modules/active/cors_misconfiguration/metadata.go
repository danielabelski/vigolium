package cors_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cors-misconfiguration"
	ModuleName  = "CORS Misconfiguration"
	ModuleShort = "Detects permissive CORS policies allowing unauthorized cross-origin access"
)

var (
	ModuleDesc = `**What it means:** The server returns a permissive CORS policy. Reproduced origin handling remains a candidate; it becomes a finding only when a browser-valid credentialed request exposes content unavailable to an unauthenticated control.

**How it's exploited:** An attacker hosts a page that performs a credentialed cross-origin request and reads protected content. Candidates still need that proof or control of a trusted origin.

**Fix:** Validate Origin against a strict allowlist of exact trusted origins, never reflect arbitrary origins, never combine the wildcard with credentials, and reject null.`

	ModuleConfirmation = "Confirmed only when reproduced attacker-origin handling, ACAC, and an authenticated-versus-unauthenticated response differential prove protected cross-origin data exposure"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "auth-bypass", "moderate"}
)
