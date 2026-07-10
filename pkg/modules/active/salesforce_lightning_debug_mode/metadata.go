package salesforce_lightning_debug_mode

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "salesforce-lightning-debug-mode"
	ModuleName  = "Salesforce Lightning Debug Mode Enabled"
	ModuleShort = "Detects a Salesforce Lightning / Experience Cloud site served in an Aura debug mode (PRODDEBUG, DEV, JSTESTDEBUG) that ships un-minified backend code and returns verbose stacktraces to unauthenticated clients"
)

var (
	ModuleDesc = `**What it means:** The Salesforce Lightning site runs in an Aura debug mode (PRODDEBUG, DEV, JSTESTDEBUG). In this mode the framework serves un-minified JavaScript and returns verbose error responses containing backend stacktraces to unauthenticated clients — an information-disclosure misconfiguration that aids reconnaissance.

**How it's exploited:** An attacker reads the Aura bootstrap mode from any community page, then triggers Aura errors to harvest backend stacktraces, class/method names and code paths guiding further attacks.

**Fix:** Set the Lightning site to production mode (disable Debug Mode in Setup) so the framework runs in PROD and suppresses backend detail.`

	ModuleConfirmation = "Confirmed when the Aura bootstrap on a live Aura gateway host declares a debug mode (PRODDEBUG / DEV / JSTESTDEBUG) consistently across independent, cache-bypassed rounds; a PROD (or STATS) mode never fires"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"salesforce", "aura", "lightning", "debug", "info-disclosure", "misconfig", "light"}
)

var moduleReferences = []string{
	"https://sebastien-copin.com/posts/sf_debug_mode",
	"https://www.enumerated.ie/index/salesforce",
}
