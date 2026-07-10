package salesforce_aura_apex_execution

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "salesforce-aura-apex-execution"
	ModuleName  = "Salesforce Aura Guest Apex Execution"
	ModuleShort = "Detects a Salesforce Experience Cloud site whose unauthenticated Guest user can invoke @AuraEnabled Apex methods through the ApexActionController.execute Aura action — the pivot for guest-driven SSRF, data exfiltration, DML and phishing"
)

var (
	ModuleDesc = `**What it means:** A Salesforce Experience Cloud site lets the unauthenticated Guest user drive the Aura ApexActionController.execute action, which dispatches into server-side @AuraEnabled Apex — arbitrary Apex reachability, the pivot for guest-driven SSRF, SOQL exfiltration, content injection, phishing and DML.

**How it's exploited:** An attacker harvests the aura.context and POSTs an ApexActionController.execute message (null guest token) naming a reachable class/method. The scanner confirms only the read-only capability with a benign managed-package method.

**Fix:** Remove @AuraEnabled Apex from the Guest profile, declare Apex classes "with sharing", enforce CRUD/FLS, and enable "Secure guest user record access".`

	ModuleConfirmation = "Confirmed when ApexActionController.execute returns state:SUCCESS for a benign read-only Apex method across independent rounds, while a bogus namespace/class/method returns a non-success state (ruling out a catch-all endpoint) — against a live Aura gateway"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"salesforce", "aura", "lightning", "apex", "rce", "ssrf", "misconfig", "heavy"}
)

var moduleReferences = []string{
	"https://sebastien-copin.com/posts/sf_apex_execution",
	"https://www.enumerated.ie/index/salesforce",
	"https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure",
}
