package salesforce_aura_record_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "salesforce-aura-record-exposure"
	ModuleName  = "Salesforce Aura Guest Record Exposure"
	ModuleShort = "Detects unauthenticated read of Salesforce SObject records (User, Contact, Case, Lead, custom __c objects) through an Experience Cloud site's Aura getItems action caused by an over-permissive Guest User profile"
)

var (
	ModuleDesc = `**What it means:** A Salesforce Experience Cloud site lets the unauthenticated Guest user read actual SObject records (Users, Contacts, Cases, Leads, custom __c objects) over the Aura getItems action — a direct leak of personal and business data. This is the "AuraInspector" / ShinyHunters exposure class.

**How it's exploited:** An attacker harvests the aura.context, enumerates objects via getConfigData, then POSTs getItems per object (paginated) to extract every record with no authentication.

**Fix:** Remove unneeded Guest User object/field read permissions, enable "Secure guest user record access", and declare Apex classes "with sharing".`

	ModuleConfirmation = "Confirmed when the Aura getItems action returns state:SUCCESS with a non-empty record set for a sensitive object, reproduced across independent rounds, while a bogus object name returns no records (ruling out a catch-all)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"salesforce", "aura", "lightning", "exposure", "info-disclosure", "idor", "misconfig"}
)

var moduleReferences = []string{
	"https://www.enumerated.ie/index/salesforce",
	"https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure",
	"https://www.varonis.com/blog/misconfigured-salesforce-experiences",
}
