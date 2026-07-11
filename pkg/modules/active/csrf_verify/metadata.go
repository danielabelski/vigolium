package csrf_verify

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csrf-verify"
	ModuleName  = "CSRF Token Verification"
	ModuleShort = "Tests token and cross-site origin enforcement using realistic forged requests"
)

var (
	ModuleDesc = `**What it means:** A state-changing request carried a CSRF token, but a cross-site-shaped request received the same response after the scanner removed, emptied, or randomized it. This is a reproduced bypass candidate; generic scanning cannot prove a durable state change safely.

**How it's exploited:** An attacker hosts a page that auto-submits a forged request while the victim is logged in. The server ignores the token, so it runs with the victim's session, triggering actions like settings changes or fund transfers.

**Fix:** Reject any state-changing request whose CSRF token is missing, empty, or invalid, and add SameSite cookies.`

	ModuleConfirmation = "Candidate when a cross-site request with a removed, emptied, or randomized token matches the valid-token response; confirmation requires a durable state change"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"csrf", "audit", "moderate"}
)
