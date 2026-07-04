package aem_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-fingerprint"
	ModuleName  = "AEM Fingerprint"
	ModuleShort = "Identifies Adobe Experience Manager (Sling/CRX/Granite) from headers, cookies, and body markers, and gates the aem_* module family"
)

var (
	ModuleDesc = `**What it means:** The target runs Adobe Experience Manager, identified passively from the Communique/Day-Servlet-Engine Server header, login-token/cq-authoring-mode cookies, the "Welcome to Adobe Experience Manager" text, and Sling/Granite/CQ asset paths. Informational technology disclosure, not a vulnerability itself.

**How it's exploited:** AEM has a large attack surface (exposed CRXDE/Package Manager, QueryBuilder and GQL servlets, the Groovy console, dispatcher bypasses). Knowing the target is AEM lets an attacker go straight for those weaknesses instead of probing blindly.

**Fix:** Remove the identifying Server header and harden the dispatcher so AEM-internal paths (/system, /crx, /bin, /libs, /etc) are not internet-reachable.`

	ModuleConfirmation = "Confirmed when AEM-specific headers, cookies, or Sling/Granite/CQ body markers are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"aem", "adobe", "cms", "fingerprint", "light"}
)
