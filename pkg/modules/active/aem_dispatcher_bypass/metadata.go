package aem_dispatcher_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-dispatcher-bypass"
	ModuleName  = "AEM Dispatcher ACL Bypass"
	ModuleShort = "Confirms an AEM Dispatcher access-control bypass by differential: a protected servlet is blocked on the direct path but reachable through a path-normalization trick"
)

var (
	ModuleDesc = `**What it means:** The AEM Dispatcher access-control layer is bypassable: a sensitive servlet (CRX package listing or QueryBuilder) is blocked directly but reachable via a path-normalization trick (;%0a…a.css, /content/..;/, or a matrix parameter). Confirmed by differential: blocked directly, served via the bypass.

**How it's exploited:** An attacker lists content packages (toward installing a malicious one for code execution) or runs QueryBuilder against /home/users to dump password hashes — unauthenticated.

**Fix:** Upgrade the Dispatcher, apply Adobe's filter rules, reject encoded newlines and /..;/ segments, and deny /crx and /bin/querybuilder at the edge.`

	ModuleConfirmation = "Confirmed when the direct request to a protected servlet does not return its content but a path-normalization bypass variant does, reproducibly"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"aem", "adobe", "acl-bypass", "path-normalization", "dispatcher", "cms", "moderate"}
)
