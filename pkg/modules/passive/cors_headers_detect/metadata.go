package cors_headers_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cors-headers-detect"
	ModuleName  = "CORS Headers Detect"
	ModuleShort = "Passively detects permissive CORS headers in responses"
)

var (
	ModuleDesc = `**What it means:** The response contains CORS posture worth active confirmation. Wildcard public access and wildcard-plus-credentials are observations; null or reflected cross-origin policies are candidates until protected data exposure is reproduced.

**How it's exploited:** Exploitation requires a browser-valid attacker origin and useful response content. Browsers reject credentialed reads when ACAO is wildcard; null/reflected origins still require active reproduction against protected content.

**Fix:** Reflect only an explicit allow-list of trusted origins, never pair a wildcard or null origin with Access-Control-Allow-Credentials, and omit CORS headers where not needed.`

	ModuleConfirmation = "Observed when a response contains permissive CORS headers; active route-aware probing is required for a confirmed protected-data exposure"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "light"}
)
