package path_relative_stylesheet

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "path-relative-stylesheet"
	ModuleName  = "Path-Relative Stylesheet Import (PRSSI)"
	ModuleShort = "Detects path-relative stylesheet imports on a page reachable via path-info confusion without nosniff"
)

var (
	ModuleDesc = `**What it means:** The page references a stylesheet with a path-relative URL, and the server serves that page when extra path segments are appended (path-info). A browser resolves the stylesheet against an attacker-influenced deeper base path, and because the response omits nosniff, attacker content can be interpreted as CSS.

**How it's exploited:** An attacker sends a victim a link with crafted trailing path segments so the stylesheet resolves to attacker-controlled content, enabling CSS injection, UI redressing, or script execution in older browsers.

**Fix:** Reference stylesheets with absolute URLs, send X-Content-Type-Options: nosniff, and do not serve content for arbitrary trailing segments.`

	ModuleConfirmation = "Confirmed when a page carrying a path-relative stylesheet is served unchanged at a path-info-confused URL (while a genuinely nonexistent sibling is not), and the response omits X-Content-Type-Options: nosniff"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"client-side", "css-injection", "prssi", "moderate"}
)
