package file_upload_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "file-upload-scan"
	ModuleName  = "File Upload Scanner"
	ModuleShort = "Tests for arbitrary file upload and execution vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** The file upload endpoint accepts a dangerous file (PHP script, .htaccess, SVG, or HTML) and stores it where it can be retrieved. The attacker controls the content and URL.

**How it's exploited:** An attacker uploads via an extension bypass (double extension, null byte, .phtml, .phar), then fetches it back. If the retrieved file returns a computed arithmetic value rather than its source, the server executed it — remote code execution; otherwise it is a stored, retrievable arbitrary file.

**Fix:** Allowlist safe extensions and content types, store uploads outside the web root, and randomize filenames.`

	ModuleConfirmation = "Confirmed when a retrieved upload returns the computed arithmetic execution signature (code execution) or is retrievable with the unique marker (arbitrary upload), or an uploaded file triggers an out-of-band interaction"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "injection", "heavy"}
)
