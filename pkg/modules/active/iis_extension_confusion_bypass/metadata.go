package iis_extension_confusion_bypass

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "iis-extension-confusion-bypass"
	ModuleName  = "IIS Extension Confusion Bypass"
	ModuleShort = "Confirms IIS path-parsing quirks: NTFS ::$DATA source disclosure and trailing-dot / ::$INDEX_ALLOCATION access bypass"
)

var (
	ModuleDesc = `**What it means:** IIS parses request paths with Windows/NTFS filename rules access controls don't expect. Appending the NTFS data stream ` + "`::$DATA`" + ` to a script file returns its raw source instead of executing it; a trailing dot or ` + "`::$INDEX_ALLOCATION`" + ` lets a request slip past a rule bound to the exact path. The scanner probes executed ` + "`.aspx`/`.asmx`/`.ashx`" + ` pages for source disclosure and 401/403 responses for bypass.

**How it's exploited:** Source disclosure leaks server-side code, connection strings, and secrets; a bypass reaches admin pages or APIs believed protected.

**Fix:** Canonicalize the path (strip trailing dots, reject alternate-data-stream syntax) before authorizing.`

	ModuleConfirmation = "Confirmed when ::$DATA returns genuine server-side source (directive markers) distinct from the rendered page and not served for a decoy path; or when an IIS-specific rewrite turns a 401/403 into a 200 with distinct real content that is not reproduced for a decoy path — each re-confirmed on a second request"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"iis", "aspnet", "access-control", "info-disclosure", "heavy"}
)
