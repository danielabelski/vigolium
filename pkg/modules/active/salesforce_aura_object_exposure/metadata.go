package salesforce_aura_object_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "salesforce-aura-object-exposure"
	ModuleName  = "Salesforce Aura Guest Object Enumeration"
	ModuleShort = "Detects a Salesforce Experience Cloud site whose Guest user can invoke the Aura getConfigData action and enumerate accessible SObjects — including custom (__c) objects — indicating an over-permissive Guest User profile"
)

var (
	ModuleDesc = `**What it means:** A Salesforce Experience Cloud site lets the unauthenticated Guest user invoke Aura actions on a public gateway. The getConfigData action returns apiNamesToKeyPrefixes — the SObjects the Guest can reach. When this includes custom (__c) objects, the Guest profile is over-permissive — the pivot for record extraction.

**How it's exploited:** An attacker harvests the aura.context, POSTs getConfigData with a null token to read the object list and discover custom objects, then extracts records via getItems.

**Fix:** Lock down the Guest User profile, use "with sharing" Apex, and enable "Secure guest user record access".`

	ModuleConfirmation = "Confirmed when the Aura getConfigData action returns state:SUCCESS with an apiNamesToKeyPrefixes map exposing custom (__c) objects to the guest, reproduced across independent rounds against a live Aura gateway"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"salesforce", "aura", "lightning", "exposure", "info-disclosure", "misconfig", "moderate"}
)

var moduleReferences = []string{
	"https://www.enumerated.ie/index/salesforce",
	"https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure",
}
