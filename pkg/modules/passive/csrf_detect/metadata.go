package csrf_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csrf-detect"
	ModuleName  = "CSRF Detection"
	ModuleShort = "Flags state-changing requests missing anti-CSRF protections"
)

var (
	ModuleDesc = `**What it means:** A cross-site-forgeable state-changing request carries a likely session cookie but no visible anti-CSRF token, custom header, or known SameSite=Strict/Lax policy. This is a candidate; passive traffic cannot prove Origin/Referer enforcement or a durable state change.

**How it's exploited:** An attacker hosts a page that auto-submits a hidden form to this endpoint. A signed-in victim who visits has their cookie replayed and the unprotected action runs - changing settings or transferring funds.

**Fix:** Require a per-session anti-CSRF token (or a server-validated custom header) on every state-changing request, and set SameSite on session cookies.`

	ModuleConfirmation = "Candidate when a forgeable, session-backed request lacks visible CSRF defenses; active cross-site replay and state verification are required"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"csrf", "session", "light"}
)
