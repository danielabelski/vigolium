package idor_params_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "idor-params-detect"
	ModuleName  = "IDOR Parameter Detection"
	ModuleShort = "Detects parameters that may reference object identifiers (IDOR/BOLA triage)"
)

var (
	ModuleDesc = `**What it means:** Informational triage, not a confirmed bug. The scanner spotted a request parameter resembling a direct object identifier (an ID name like user_id or account_id with a predictable value), or a JSON response exposing sensitive fields (password_hash, ssn, is_admin) - common locations for IDOR/BOLA flaws.

**How it's exploited:** No request was sent, so exploitability is unconfirmed. For follow-up, an attacker swaps the identifier for another user's value and checks whether the response returns that object's data.

**Fix:** Enforce per-object authorization on every request so users only access identifiers they own, and avoid returning sensitive internal fields.`

	ModuleConfirmation = "Observation for likely object identifiers; sensitive response fields remain candidates until role/identity authorization is compared"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"idor", "authentication", "light"}
)
