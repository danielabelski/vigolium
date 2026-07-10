package aem_console_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-console-exposure"
	ModuleName  = "AEM Console & Admin Panel Exposure"
	ModuleShort = "Detects internet-reachable AEM developer/admin consoles (CRXDE Lite, CRX Package Manager, CRX Explorer, admin dashboards) and dispatcher ACL bypasses to them"
)

var (
	ModuleDesc = `**What it means:** An AEM developer/admin console (CRXDE Lite, CRX Package Manager, Content Explorer, user admin) is internet-reachable; these belong on internal networks only. Confirmed over several rounds, with any dispatcher path-normalization bypass reported.

**How it's exploited:** An attacker browses the JCR via CRXDE Lite, installs a malicious content package (a route to code execution), or enumerates users — often unauthenticated.

**Fix:** Block /crx, /system/console, and /etc admin tooling at the dispatcher, remove default credentials, and keep author consoles off untrusted networks.`

	ModuleConfirmation = "Confirmed when an AEM console/admin panel's unique title/markers are served with a 200 and reproduce across multiple confirmation rounds"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aem", "adobe", "misconfiguration", "exposure", "cms", "light"}
)
