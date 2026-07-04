package aem_oob_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-oob-injection"
	ModuleName  = "AEM Blind SSRF / XXE (Out-of-Band)"
	ModuleShort = "Fires out-of-band probes for the AEM AccessTokenServlet full-read SSRF (CVE-2025-54249) and the CRX Package Manager blind XXE (CVE-2025-54251); a callback to the collaborator confirms the vulnerability"
)

var (
	ModuleDesc = `**What it means:** Two AEM endpoints fetch attacker-controlled resources server-side. The AccessTokenServlet (` + "`/services/accesstoken/verify`" + `) requests the URL in the ` + "`auth_url`" + ` parameter and returns the body (full-read SSRF, CVE-2025-54249). The CRX Package Manager parses an uploaded package's ` + "`privileges.xml`" + ` with an XXE-unsafe parser (CVE-2025-54251).

**How it's exploited:** POST ` + "`auth_url=http://<collaborator>/`" + `, or upload a package whose ` + "`privileges.xml`" + ` declares an external entity pointing at the collaborator; a DNS/HTTP interaction confirms it.

**Fix:** Apply the GRANITE-61551 hotfix (AEM 6.5.23+), block ` + "`/services/accesstoken`" + ` and ` + "`/crx/packmgr`" + ` at the dispatcher, and disable external-entity resolution in the package-manager parser.`

	ModuleConfirmation = "Confirmed out-of-band: the AEM server issues a DNS/HTTP request to the collaborator host planted in auth_url or in the uploaded package's privileges.xml SYSTEM entity"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aem", "adobe", "ssrf", "xxe", "oob", "blind", "cve", "cve2025", "cms"}
)
