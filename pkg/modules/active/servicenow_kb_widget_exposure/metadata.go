package servicenow_kb_widget_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "servicenow-kb-widget-exposure"
	ModuleName  = "ServiceNow Knowledge Base Widget Exposure"
	ModuleShort = "Detects unauthenticated read of ServiceNow Knowledge Base article contents through the public KB Article Page Service Portal widget, which the 2023 ACL hardening does not cover (KB access is gated by User Criteria, not ACLs)"
)

var (
	ModuleDesc = `**What it means:** A ServiceNow instance exposes Knowledge Base article bodies to guests through the public KB Article Page widget. Knowledge articles are gated by User Criteria, not table ACLs, so the 2023 ACL hardening does not protect them — KB content (often internal procedures, credentials, tokens) stays guest-readable.

**How it's exploited:** An attacker gets a guest session and token, then POSTs the KB widget with ?sys_id=KB0000001. KB numbers are sequential, so an attacker enumerates them. A non-empty text/short_description confirms the leak.

**Fix:** Restrict Knowledge Base User Criteria so guests cannot read internal KBs; remove secrets from articles.`

	ModuleConfirmation = "Confirmed when a KB Article Page widget POST returns a non-empty article text/short_description for a guest, reproduced across independent rounds, while a non-existent KB id returns no content (ruling out a catch-all)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"servicenow", "exposure", "info-disclosure", "idor", "api", "misconfig"}
)

var moduleReferences = []string{
	"https://www.enumerated.ie/index/servicenow-data-exposure",
	"https://appomni.com/ao-labs/servicenow-knowledge-bases-data-exposures-uncovered/",
}
