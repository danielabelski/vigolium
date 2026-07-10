package aem_xss

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-xss"
	ModuleName  = "AEM Reflected XSS"
	ModuleShort = "Detects reflected XSS in AEM-specific sinks (childlist selector, CRXDE setPreferences, DAM merge-metadata, WCM contentfinder) with headless popup confirmation"
)

var (
	ModuleDesc = `**What it means:** An AEM servlet reflects input into an HTML response without encoding, allowing reflected XSS. These sinks abuse selector handling to render a JSON servlet as text/html. Graded: the unencoded breakout must survive multiple rounds, and High is only reported when a headless browser fires the alert.

**How it's exploited:** An attacker sends a victim a crafted AEM URL; the payload runs in the victim's session, enabling session theft or author-console actions.

**Fix:** Encode reflected output, restrict the affected selectors at the dispatcher, and apply Adobe's XSS hotfixes for CRXDE, DAM, and contentfinder.`

	ModuleConfirmation = "Confirmed when the injected breakout reflects unencoded in a text/html response across multiple rounds; escalated to High when a headless browser fires the alert dialog"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aem", "adobe", "xss", "cms", "moderate"}
)
