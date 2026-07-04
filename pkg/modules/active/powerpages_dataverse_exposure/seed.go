package powerpages_dataverse_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

// dvTable is a Dataverse entity set probed for anonymous read exposure. set is
// the OData collection name used in /_api/<set>; sev reflects the sensitivity of
// the data the table holds when it leaks.
//
// The list is limited to genuinely sensitive standard tables plus adx_sitesetting
// (which can hold portal secrets). Portal-content tables (adx_webpage,
// adx_contentsnippet, adx_weblinkset) are intentionally excluded: anonymous read
// of those is by-design (they ARE the rendered site), so reporting them would be
// a false positive.
type dvTable struct {
	set   string
	label string
	sev   severity.Severity
}

// seedTables is enumerated in full on every confirmed Power Pages host.
var seedTables = []dvTable{
	{"contacts", "Contacts — personal data (names, emails, phones, addresses)", severity.Critical},
	{"leads", "Leads — prospect personal data", severity.Critical},
	{"systemusers", "System Users — internal staff accounts", severity.Critical},
	{"accounts", "Accounts — organization records", severity.High},
	{"incidents", "Cases / Incidents — support ticket contents", severity.High},
	{"annotations", "Notes & Attachments — free-text notes and file bodies", severity.High},
	{"opportunities", "Opportunities — sales pipeline", severity.High},
	{"emails", "Email activities — message contents", severity.High},
	{"sharepointdocuments", "SharePoint documents — linked files", severity.High},
	{"activitypointers", "Activities — task/appointment/phone-call records", severity.Medium},
	{"adx_sitesettings", "Portal site settings — configuration (may include secrets)", severity.Medium},
}
