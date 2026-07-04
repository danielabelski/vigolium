package servicenow_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "servicenow-fingerprint"
	ModuleName  = "ServiceNow Detection"
	ModuleShort = "Identifies ServiceNow instances from vendor hostnames, glide_* session cookies, and the g_ck / window.NOW page markers, marking the host so the servicenow_* active family gates onto real ServiceNow"
)

var (
	ModuleDesc = `**What it means:** The target is a ServiceNow instance. ServiceNow Service Portal widgets can expose arbitrary table and Knowledge Base data to unauthenticated users when table ACLs are misconfigured.

**How it's exploited:** Not itself a vulnerability. This fingerprint gates the active checks that probe the public Simple List and KB Article Page widgets for guest data exposure.

**Fix:** Not applicable — hardening lives in the table ACLs, widget public flags, and Knowledge Base User Criteria.`

	ModuleConfirmation = "Confirmed when a ServiceNow vendor hostname, a glide_* session cookie, or the g_ck / window.NOW / GlideForm page markers are observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"fingerprint", "servicenow", "itsm"}
)
