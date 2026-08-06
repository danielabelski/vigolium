package ssti_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssti-blind"
	ModuleName  = "Blind Server-Side Template Injection (SSTI)"
	ModuleShort = "Detects blind SSTI via OAST callbacks and time-delay payloads"
)

var (
	ModuleDesc = `**What it means:** User input reaches a server-side template engine (Jinja2, Twig, Freemarker, ERB, or a JVM engine — Spring EL, Thymeleaf, Velocity, OGNL/Struts) and is evaluated as template code, not data. The attacker controls code inside the engine; the blind response looks unchanged.

**How it's exploited:** Confirmed via an out-of-band callback — a shell nslookup, or a pure-JVM DNS/URL resolution where process execution is sandboxed — or paired heavy/trivial loops whose delay flags a time-based signal. An attacker escalates to remote code execution.

**Fix:** Never pass untrusted input into template source; render user data only through escaped variables.`

	ModuleConfirmation = "Confirmed via OAST DNS callback from template evaluation or consistent time-delay differential"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "ssti", "heavy"}
)
