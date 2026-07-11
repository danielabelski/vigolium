package idor_detection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "idor-detection"
	ModuleName  = "IDOR Detection"
	ModuleShort = "Detects missing authorization on object ID parameters (IDOR/BOLA)"
)

var (
	ModuleDesc = `**What it means:** Changing a direct object reference produced a stable, structurally similar response containing different object data. This is a strong IDOR/BOLA candidate, but a single identity cannot establish that the neighboring object is unauthorized.

**How it's exploited:** An attacker substitutes the ID with a neighbor value (user_id=42 to 41/43). Here the server returned a structurally similar but different response instead of 401/403/404, so IDs can be enumerated to harvest other users' data.

**Fix:** Enforce object-level authorization on every request by verifying the session may access the referenced object, and prefer unpredictable identifiers.`

	ModuleConfirmation = "Candidate when a neighbor object ID produces a stable cross-object differential; confirmation requires cross-identity or cross-tenant authorization proof"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"idor", "auth-bypass", "moderate"}
)
