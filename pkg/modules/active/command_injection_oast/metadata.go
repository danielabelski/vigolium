package command_injection_oast

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "command-injection-oast"
	ModuleName  = "OS Command Injection (Out-of-Band)"
	ModuleShort = "Detects blind OS command injection via out-of-band DNS/HTTP callbacks"
)

var (
	ModuleDesc = `**What it means:** The application passes attacker-controlled input into an OS shell command. This blind variant returns no output, so it is confirmed out-of-band: an injected command makes the server contact a unique OAST domain the scanner planted.

**How it's exploited:** An attacker appends shell commands (nslookup, curl) to a parameter or header fed into a shell. An HTTP-fetch callback proves execution (Critical); a DNS-only callback is downgraded on client-IP/forwarding headers (X-Forwarded-For, X-Real-IP), since edge infrastructure resolves those for geo-IP with no shell running.

**Fix:** Never pass user input to shell commands; use parameterized library calls and allowlist unavoidable arguments.`

	ModuleConfirmation = "Confirmed when an injected command causes the target to resolve or fetch a unique, correlated OAST subdomain"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "command-injection", "oast", "moderate"}
)
