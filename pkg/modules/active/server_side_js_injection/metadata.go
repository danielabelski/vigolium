package server_side_js_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "server-side-js-injection"
	ModuleName  = "Server-Side JavaScript Injection"
	ModuleShort = "Detects server-side JavaScript (Node.js) code injection via OAST callbacks and busy-wait timing"
)

var (
	ModuleDesc = `**What it means:** User input reaches a server-side JavaScript runtime (Node.js) and is evaluated as code — via eval, Function, vm, or a $where clause — rather than treated as data. The attacker controls JavaScript running on the server.

**How it's exploited:** Confirmed via an out-of-band request from the runtime, or a busy-wait payload whose consistent, duration-scaled delay flags a time-based signal. An attacker escalates this to remote code execution through child_process or the require chain.

**Fix:** Never pass untrusted input to eval, Function, vm, or a $where clause; parse data with safe deserializers and validate against a strict schema.`

	ModuleConfirmation = "Confirmed via an out-of-band callback from server-side JavaScript execution, or a consistent busy-wait time-delay differential across interleaved probes"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "ssji", "nodejs", "rce", "heavy"}
)
