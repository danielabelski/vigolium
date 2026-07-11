package permissions_policy_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "permissions-policy-detect"
	ModuleName  = "Permissions Policy Detect"
	ModuleShort = "Detects missing or overly permissive Permissions-Policy headers"
)

var (
	ModuleDesc = `**What it means:** Permissions-Policy grants a sensitive browser feature to all origins, or legacy Feature-Policy remains. Absence alone is ignored because need depends on feature and iframe use. This is an observation.

**How it's exploited:** With XSS or untrusted iframes, a permissive policy can let attacker code reach privileged browser APIs.

**Fix:** Send a Permissions-Policy header that disables or scopes sensitive features (camera=(), microphone=(), geolocation=(self)) and replace any legacy Feature-Policy header.`

	ModuleConfirmation = "Observed when an explicit policy is overly permissive or legacy; missing policy alone is ignored"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "misconfiguration", "light"}
)
