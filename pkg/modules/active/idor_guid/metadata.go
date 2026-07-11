package idor_guid

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "idor-guid"
	ModuleName  = "IDOR GUID Predictability"
	ModuleShort = "Detects predictable GUID patterns like UUIDv1 with extractable timestamps"
)

var (
	ModuleDesc = `**What it means:** An object-reference parameter is predictable, and the app served a stable different object for a guessed neighbor. This remains a candidate until a second identity or tenant proves unauthorized access.

**How it's exploited:** The scanner derives nearby UUIDv1 or numeric identifiers and replays them. A distinct successful response suggests an attacker could enumerate objects.

**Fix:** Enforce per-object authorization and use unpredictable, non-sequential identifiers such as random UUIDv4 instead of UUIDv1 or auto-increment IDs.`
	ModuleConfirmation = "Candidate when a predicted neighbor identifier returns a stable distinct object; confirmation requires cross-identity or cross-tenant authorization proof"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"idor", "auth-bypass", "moderate"}
)
