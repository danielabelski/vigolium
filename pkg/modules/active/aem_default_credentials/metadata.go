package aem_default_credentials

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-default-credentials"
	ModuleName  = "AEM Default Credentials"
	ModuleShort = "Detects AEM default and demo-account credentials on the Granite login and Felix Web Console"
)

var (
	ModuleDesc = `**What it means:** An AEM instance accepts a well-known default or demo credential (admin:admin, author:author, Geometrixx users, or the OSGi console admin:admin). Confirmed by differential: a wrong credential is rejected first, then the default authenticates and reproduces.

**How it's exploited:** With admin:admin an attacker signs into the author instance, CRX Package Manager, and OSGi console — where OSGi bundles can be installed for remote code execution.

**Fix:** Change or remove every default and sample credential and the sample content packages, and restrict the author instance and OSGi console to trusted networks.`

	ModuleConfirmation = "Confirmed when a deliberately-invalid credential is rejected but a default credential authenticates (login-token issued / console served), reproducibly"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"aem", "adobe", "default-credentials", "auth", "cms", "moderate"}
)
