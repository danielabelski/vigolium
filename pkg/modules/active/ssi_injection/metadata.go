package ssi_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssi-injection"
	ModuleName  = "Server-Side Includes (SSI) Injection"
	ModuleShort = "Detects Server-Side Includes injection via a directive-echo differential and out-of-band exec"
)

var (
	ModuleDesc = `**What it means:** User input reaches a page the web server parses for Server-Side Includes (SSI) and is evaluated as a directive rather than data. The scanner injected a set/echo directive whose value is emitted only when SSI is processed, with the markup consumed — proving evaluation, not reflection.

**How it's exploited:** An attacker injects directives to disclose server variables, read files, or run OS commands via the exec directive, which can lead to remote code execution.

**Fix:** Do not render untrusted input into SSI-parsed pages, disable the exec directive, and HTML-encode user data.`

	ModuleConfirmation = "Confirmed when an injected set/echo SSI directive emits its unique value with the directive markup consumed (repeated with a fresh value), or an SSI exec directive triggers an out-of-band interaction"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "ssi", "rce", "heavy"}
)
