package salesforce_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "salesforce-fingerprint"
	ModuleName  = "Salesforce Experience Cloud Detection"
	ModuleShort = "Identifies Salesforce Experience Cloud / Lightning (Aura) sites from vendor hostnames and Aura framework markers, marking the host so the salesforce_* active family gates onto real Salesforce communities"
)

var (
	ModuleDesc = `**What it means:** The target is a Salesforce Experience Cloud (community) / Lightning site served through the Aura framework. These sites expose a public Aura gateway (/s/sfsites/aura) that, when the Guest User profile is over-permissive, lets an unauthenticated attacker enumerate and read SObject records.

**How it's exploited:** Not itself a vulnerability. This fingerprint gates the active checks that probe the Aura gateway for guest object enumeration and record exposure.

**Fix:** Not applicable — hardening lives in the Guest User profile and site security settings.`

	ModuleConfirmation = "Confirmed when a Salesforce vendor hostname or Aura framework markers (siteforce:communityApp, /s/sfsites/, window.Aura, aura:invalidSession) are observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"fingerprint", "salesforce", "aura", "lightning", "crm"}
)
