package aem_xxe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-xxe"
	ModuleName  = "AEM Adaptive Forms XXE (entity processing)"
	ModuleShort = "Detects XML external entity processing in AEM Adaptive Forms guideContainer internalsubmit (CVE-2019-8086) via an exploit-free internal-entity expansion proof"
)

var (
	ModuleDesc = `**What it means:** An AEM Adaptive Forms guideContainer parses attacker-controlled guidePrefillXml with a DTD/entity-processing parser (CVE-2019-8086). Detection-only: the probe defines an internal entity expanding to a benign marker and observes expansion. No external entity, file read, or callback is used, but entity expansion means full XXE is possible.

**How it's exploited:** An attacker swaps the internal entity for SYSTEM "file:///etc/passwd" to read files or make the server request internal systems.

**Fix:** Apply Adobe's APSB19-48 hotfix, disable external-entity processing, and block the .af.internalsubmit.json selector at the dispatcher.`

	ModuleConfirmation = "Confirmed when an internal XML entity is expanded (not echoed) in the servlet response across multiple rounds, proving DTD/entity processing is enabled"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aem", "adobe", "xxe", "cve", "cve2019", "cms", "moderate"}
)
