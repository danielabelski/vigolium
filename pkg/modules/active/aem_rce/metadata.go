package aem_rce

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-rce-surface"
	ModuleName  = "AEM RCE-Capable Surface Exposure"
	ModuleShort = "Detects exposed AEM code-execution surfaces (Groovy Console, ACS Fiddle, Forms GetDocumentServlet, WebDAV PUT) without sending any exec/write payload"
)

var (
	ModuleDesc = `**What it means:** An AEM surface capable of code execution or arbitrary write is reachable. Detection-only: it confirms exposure of the Groovy Console, ACS Fiddle, the Forms GetDocumentServlet deserialization endpoint (CVE-2025-49533), or a WebDAV PUT path, but sends no script, gadget, or write.

**How it's exploited:** The Groovy Console or Fiddle run arbitrary code (RCE); GetDocumentServlet deserializes a gadget for pre-auth RCE; an anonymous PUT writes a script into the repository.

**Fix:** Remove or auth-gate the Groovy Console and Fiddle, patch AEM Forms, disable anonymous WebDAV writes, and block these paths at the dispatcher.`

	ModuleConfirmation = "Confirmed when an RCE/write-capable AEM surface serves its identifying markers (or advertises write methods) reproducibly; no exec or write payload is sent"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aem", "adobe", "rce", "exposure", "cms", "heavy"}
)
