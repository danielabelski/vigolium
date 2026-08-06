package react_rsc_rce

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "react-rsc-rce"
	ModuleName  = "React Server Components Remote Code Execution"
	ModuleShort = "Detects the React Server Components server-action decoder RCE (CVE-2025-55182 / CVE-2025-66478)"
)

var (
	ModuleDesc = `**What it means:** A Next.js / React Server Components app decodes a server-action body with a vulnerable React Flight decoder. A crafted, colon-delimited object reference makes the decoder dereference a missing property, throwing during deserialization — the primitive behind the "React2Shell" chain.

**How it's exploited:** An attacker sends one POST to the app root with a server-action header and a body carrying the crafted reference; the exception surfaces as a Next.js error digest. On affected versions this escalates to remote code execution.

**Fix:** Upgrade Next.js / React to a patched release and restrict which server actions accept untrusted input.`

	ModuleConfirmation = "Confirmed when the crafted server-action request returns a 500 with a Next.js error digest while a benign control request with a well-formed reference does not, on a host fingerprinted as Next.js"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "react", "rce", "deserialization", "cve-2025-55182", "cve-2025-66478", "heavy"}
)
