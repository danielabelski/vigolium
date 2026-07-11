package hsts_preload_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "hsts-preload-audit"
	ModuleName  = "HSTS Preload Audit"
	ModuleShort = "Audits Strict-Transport-Security header for preload readiness"
)

var (
	ModuleDesc = `**What it means:** An existing HSTS policy is not ready for optional browser preload because max-age, includeSubDomains, or preload requirements are absent. This is operational posture, not a vulnerability; missing HSTS is reported once by the generic browser-policy observation.

**How it's exploited:** A network attacker (rogue Wi-Fi, ARP spoofing, proxy) intercepts a first or non-HTTPS request and strips TLS or serves a forged certificate, downgrading to plaintext to read or modify traffic including session cookies.

**Fix:** Send Strict-Transport-Security: max-age=31536000; includeSubDomains; preload on all HTTPS responses and submit the domain to the preload list.`

	ModuleConfirmation = "Confirmed when HSTS header is missing, incomplete, or not preload-ready"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "cryptography", "light"}
)
