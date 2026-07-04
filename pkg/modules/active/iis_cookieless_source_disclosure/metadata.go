package iis_cookieless_source_disclosure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "iis-cookieless-source-disclosure"
	ModuleName  = "IIS Cookieless Source/Config Disclosure"
	ModuleShort = "Downloads protected ASP.NET config/source via cookieless (S(X)) path-confusion (per-host)"
)

var (
	ModuleDesc = `**What it means:** ASP.NET cookieless session tokens (the ` + "`(S(...))`" + ` URL segments) are stripped from the path after IIS request filtering runs, so inserting a throwaway token lets a request reach a file the filter would block — web.config, machine.config, global.asax, and more. The scanner requests each named file directly and through several cookieless bypass shapes.

**How it's exploited:** web.config leaks the machineKey (enabling ViewState forgery and RCE via ysoserial.net), connection strings, and credentials; source files leak application logic.

**Fix:** Keep request filtering enabled, disable cookieless sessions, encrypt config sections or store secrets elsewhere, and rotate any exposed machine keys.`

	ModuleConfirmation = "Confirmed only when a cookieless bypass returns the genuine artifact (structural content markers such as <configuration>+machineKey, or a global.asax application block), the same shape on a random non-existent file does NOT (decoy negative), and the result reproduces on re-request"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"iis", "aspnet", "info-disclosure", "cookieless", "heavy"}
)
