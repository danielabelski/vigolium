package js_beautify

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "js-beautify"
	ModuleName  = "JavaScript Beautifier"
	ModuleShort = "Unminifies and unpacks JavaScript bundles into readable, module-annotated source"
)

var (
	ModuleDesc = `**What it means:** A minified or webpack/browserify-bundled first-party script (React/Next/Vue SPA) was unminified and, when a bundle, split into per-module source with recovered paths. Informational, not a vulnerability. Vendor and non-minified scripts are skipped. For JS responses the stored body is replaced with the beautified document and tagged ` + "`js-beautified`" + `; inline scripts go to evidence only.

**How it's exploited:** Readable source speeds endpoint discovery and reverse engineering; internal APIs and hidden routes become legible.

**Fix:** Not a defect; to limit exposure, avoid shipping source maps and keep secrets server-side.`

	ModuleConfirmation = "Emitted when a minified or bundled first-party script was successfully unminified/unpacked into a document that differs from the original"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"javascript", "beautify", "deobfuscation", "recon", "source-analysis", "light"}
)
