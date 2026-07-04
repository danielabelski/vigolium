package powerpages_dataverse_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "powerpages-dataverse-exposure"
	ModuleName  = "Power Pages Dataverse Web API Data Exposure"
	ModuleShort = "Detects unauthenticated read access to Microsoft Dataverse tables (contacts, accounts, leads, cases, custom tables) through a Power Pages portal's /_api/ Web API caused by an over-permissive Anonymous Users table permission"
)

var (
	ModuleDesc = `**What it means:** A Microsoft Power Pages portal exposes Dataverse tables to anonymous callers over the Web API (/_api/<entityset>). A Table Permission granting the Anonymous Users role read access, plus a wildcard column allow-list, lets anyone read CRM records — names, emails, addresses, cases — with an unauthenticated GET.

**How it's exploited:** An attacker sends ` + "`GET /_api/contacts`" + ` with no token. A 200 with an @odata.context and a value array confirms the table is readable; the attacker then pages the whole table.

**Fix:** Restrict Table Permissions for the Anonymous Users role, minimize the Web API column allow-list, and mask PII columns.`

	ModuleConfirmation = "Confirmed when an unauthenticated GET /_api/<table> returns HTTP 200 with an @odata.context and a non-empty value array of records, reproduced across independent rounds, while a bogus entity set returns a Dataverse 404 (ruling out a catch-all)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"powerpages", "dataverse", "microsoft", "exposure", "info-disclosure", "idor", "api"}
)

var moduleReferences = []string{
	"https://appomni.com/ao-labs/microsoft-power-pages-data-exposure-reviewed/",
	"https://learn.microsoft.com/en-us/power-pages/configure/web-api-http-requests-handle-errors",
}
