package powerpages_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "powerpages-fingerprint"
	ModuleName  = "Microsoft Power Pages Detection"
	ModuleShort = "Identifies Microsoft Power Pages / Power Apps portals (Dataverse-backed) from vendor hostnames, portal cookies, and the Web API AJAX wrapper, marking the host so the powerpages_* active family gates onto real portals"
)

var (
	ModuleDesc = `**What it means:** The target is a Microsoft Power Pages (Power Apps portals) site backed by Microsoft Dataverse. Portal data is served through the Dataverse Web API at /_api/<entityset>, governed by Table Permissions and web roles.

**How it's exploited:** Power Pages sites frequently grant the Anonymous Users role read access to Dataverse tables with a wildcard column allow-list, letting an unauthenticated attacker read CRM records over OData. This fingerprint gates the active exposure check.

**Fix:** Not itself a vulnerability. Review Table Permissions and Web API site settings so no sensitive table is readable by the Anonymous Users role.`

	ModuleConfirmation = "Confirmed when a Power Pages vendor hostname, the Dynamics365PortalAnalytics/locale portal cookies, or the shell.getTokenDeferred / webapi.safeAjax Web API wrapper is observed"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"fingerprint", "powerpages", "dataverse", "microsoft", "aspnet"}
)
