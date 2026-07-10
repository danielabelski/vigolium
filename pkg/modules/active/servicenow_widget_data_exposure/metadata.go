package servicenow_widget_data_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "servicenow-widget-data-exposure"
	ModuleName  = "ServiceNow Public Widget Data Exposure"
	ModuleShort = "Detects unauthenticated read of arbitrary ServiceNow tables (sys_user, incident, cmdb_ci, attachments, OAuth entities) through the public Simple List / Unordered List Service Portal widgets caused by allow-all table ACLs"
)

var (
	ModuleDesc = `**What it means:** A ServiceNow instance exposes arbitrary table data to guests through a public Service Portal widget. The Simple List / Unordered List widgets wrap a GlideRecordSecure query over an attacker-supplied table (t=). With allow-all table ACLs, a guest reads tables such as sys_user, cmdb_ci, incident, sys_attachment, and oauth_entity.

**How it's exploited:** An attacker gets a guest session and CSRF (g_ck) token, then POSTs /api/now/sp/widget/widget-simple-list?t=sys_user with X-UserToken. isValid:true, count>0, and real display_values confirm the leak; the attacker pages the whole table.

**Fix:** Restrict the affected table ACLs (never leave role/condition/script empty) and scope or unpublish the list widgets.`

	ModuleConfirmation = "Confirmed when a Simple List widget POST returns isValid:true, count>0, and a first record with a non-null display_value for a sensitive table, reproduced across independent rounds, while a bogus table returns no records (ruling out a catch-all) and a missing token returns 401"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"servicenow", "exposure", "info-disclosure", "idor", "api", "misconfig", "moderate"}
)

var moduleReferences = []string{
	"https://www.enumerated.ie/index/servicenow-data-exposure",
	"https://github.com/aaron-costello/ServiceNow-Schema",
}
