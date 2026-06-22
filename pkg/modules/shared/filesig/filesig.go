// Package filesig provides shared structural confirmation that a leaked
// server-side file's real content appears in a response. It is the single
// source of truth for the LFI / path-traversal / file-read scanner modules
// (lfi_path_traversal, mcp_resource_fuzz, mcp_tool_fuzz, …) so they don't each
// re-implement — and drift on — "does this body actually contain /etc/passwd?".
//
// Every confirmer requires the file's actual structural shape (a real passwd
// account line, a bracketed win.ini section, an anchored nginx/apache directive)
// and subtracts the baseline, replacing the bare-word substring markers that
// modules historically used. Bare words ("root:", ":0:0:", "/bin/", "server",
// "location", "fonts", "extensions") are ordinary English / appear in CSP
// directives, JSON keys, error strings, and HTML, so they matched responses
// that contain no file content at all. The motivating false positive: a
// Cloudflare 403 "Blocked Content" page whose embedded cf-beacon JSON carried
// "server_timing" and "location_startswith" satisfied an LFI module's bare
// "server"/"location" nginx.conf markers and was reported as High/Firm LFI.
//
// These confirmers do NOT inspect the response status — a caller that fronts a
// WAF/CDN must still reject blocked / challenge / 4xx-5xx responses before
// confirming (see infra.IsBlockedResponse). Structural confirmation and the
// status gate are complementary: the gate drops the edge talking, the confirmer
// drops everything that does not carry the file.
package filesig

import (
	"regexp"
	"strings"
)

// ConfirmFunc structurally corroborates that a leaked file's real content
// appears in data and was not already present in baseline. It returns whether
// the read is confirmed and a score (the number of distinct new, file-shaped
// matches) callers can use to grade confidence (e.g. >=3 ⇒ Certain).
type ConfirmFunc func(data, baseline string) (ok bool, score int)

// --- Linux /etc/passwd -------------------------------------------------------
//
// Unlike the other confirmers here, the passwd matchers are NOT line-anchored.
// passwd is the universal LFI canary, probed both by direct file-read modules
// (where the file's bytes land at the start of the response body) and by
// transports that wrap the leaked content inside a structured envelope — most
// notably MCP, whose resources/read and tools/call replies carry the file as a
// JSON-RPC `"text":"…"` value, mid-line. A line-anchored `^root:` would silently
// miss every MCP leak. Instead the shape is pinned by two boundaries:
//
//   - a leading word boundary (\b) so `root:` is a token start, not the tail of
//     `chroot:`; and
//   - a TRAILING boundary on the shell field — the entry must end at a line or
//     value terminator (newline, an escaped "\n", a closing quote/comma, or
//     EOF). This is the discriminator that rejects a `root:x:0:0:root:/root:/bin/
//     bash is the superuser entry` sentence reflected in prose/JSON: a real
//     entry's shell field is terminated, a sentence continues with " is …".
//
// The numeric uid:gid fields and the home/shell shape keep it from matching
// arbitrary colon-separated data.

// passwdEntryTail is the shared shell-field-plus-terminator suffix: a shell path
// (no whitespace/quote/comma/colon/backslash) that ends at a value/line boundary.
const passwdEntryTail = `[^\s:",\\]*(?:\\|"|,|\r|\n|$)`

// passwdRootRe matches the root entry: uid 0, gid 0, a GECOS field, a home
// directory, and a terminated shell field. It is the gate for a confirmed leak.
var passwdRootRe = regexp.MustCompile(`\broot:[^:\r\n"]{0,64}:0:0:[^:\r\n"]{0,64}:[^:\r\n"]{0,128}:` + passwdEntryTail)

// passwdEntryRe matches any account entry (any uid/gid) and is used only to
// score how many distinct entries leaked.
var passwdEntryRe = regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_.-]{0,31}:[^:\r\n"]{0,64}:\d{1,7}:\d{1,7}:[^:\r\n"]{0,64}:[^:\r\n"]{0,128}:` + passwdEntryTail)

// ConfirmPasswd confirms a leaked /etc/passwd: a root uid 0/gid 0 entry with a
// terminated shell field must appear that is absent from the baseline.
func ConfirmPasswd(data, baseline string) (bool, int) {
	if !hasNewMatch(passwdRootRe, data, baseline) {
		return false, 0
	}
	n := countNewDistinctMatches(passwdEntryRe, data, baseline)
	if n < 1 {
		n = 1
	}
	return true, n
}

// --- Linux /etc/shadow -------------------------------------------------------

// shadowLineRe matches a shadow entry whose second field is a crypt hash
// ($1$/$5$/$6$/$y$/$2a$/$2y$ …) — unambiguous file content.
var shadowLineRe = regexp.MustCompile(`(?m)^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}:\$(1|2a|2b|2y|5|6|y)\$[^:\r\n]{2,}:`)

// ConfirmShadow confirms a leaked /etc/shadow by a new crypt-hash line.
func ConfirmShadow(data, baseline string) (bool, int) {
	n := countNewDistinctMatches(shadowLineRe, data, baseline)
	if n < 1 {
		return false, 0
	}
	return true, n + 2 // a real shadow hash is high-confidence on its own
}

// --- Linux /etc/hosts --------------------------------------------------------

// hostsLocalhostRe anchors a genuine hosts file: the canonical loopback→localhost
// mapping every /etc/hosts carries, at line start.
var hostsLocalhostRe = regexp.MustCompile(`(?mi)^[ \t]*(127\.0\.0\.1|::1)[ \t]+[a-z0-9.-]*localhost`)

// hostsLineRe matches any IPv4 host-mapping line for scoring.
var hostsLineRe = regexp.MustCompile(`(?m)^[ \t]*(\d{1,3}\.){3}\d{1,3}[ \t]+[A-Za-z0-9]`)

// ConfirmHosts confirms a leaked /etc/hosts by the localhost-mapping anchor.
func ConfirmHosts(data, baseline string) (bool, int) {
	if !hasNewMatch(hostsLocalhostRe, data, baseline) {
		return false, 0
	}
	n := countNewDistinctMatches(hostsLineRe, data, baseline)
	if n < 1 {
		n = 1
	}
	return true, n
}

// --- Linux /proc/self/environ ------------------------------------------------

// environVarRe matches a process environment assignment (KEY=value). /proc/self/
// environ is NUL-separated, so the match is not line-anchored; requiring two
// distinct well-known variables keeps a single reflected query-string `PATH=…`
// from confirming.
var environVarRe = regexp.MustCompile(`(?:^|[\x00\s])(PATH|HOME|USER|PWD|SHELL|HOSTNAME|LANG|TERM|SHLVL|LOGNAME|HTTP_HOST|SERVER_SOFTWARE)=[^\s&;]`)

// ConfirmEnviron confirms a leaked /proc/self/environ by two distinct env vars.
func ConfirmEnviron(data, baseline string) (bool, int) {
	n := countNewDistinctMatches(environVarRe, data, baseline)
	if n < 2 {
		return false, 0
	}
	return true, n
}

// --- Linux /proc/version -----------------------------------------------------

// procVersionRe matches the kernel banner, e.g. "Linux version 5.15.0-…".
var procVersionRe = regexp.MustCompile(`Linux version \d+\.\d+`)

// ConfirmProcVersion confirms a leaked /proc/version by the kernel banner.
func ConfirmProcVersion(data, baseline string) (bool, int) {
	if hasNewMatch(procVersionRe, data, baseline) {
		return true, 3
	}
	return false, 0
}

// --- Windows win.ini ---------------------------------------------------------

// winIniSectionRe matches a bracketed win.ini section header at line start. The
// former bare words "fonts"/"extensions" fired on CSP `font-src` directives and
// any HTML mentioning them.
var winIniSectionRe = regexp.MustCompile(`(?im)^\[(fonts|extensions|mci extensions|files|mail|ports|devices|sound|drivers|boot|386enh)\]`)

// ConfirmWinIni confirms a leaked win.ini by two distinct bracketed sections.
func ConfirmWinIni(data, baseline string) (bool, int) {
	n := countNewDistinctMatches(winIniSectionRe, data, baseline)
	if n < 2 {
		return false, 0
	}
	return true, n
}

// --- Windows boot.ini --------------------------------------------------------

var bootIniSectionRe = regexp.MustCompile(`(?im)^\[(boot loader|operating systems)\]`)

// ConfirmBootIni confirms a leaked boot.ini by its two canonical sections.
func ConfirmBootIni(data, baseline string) (bool, int) {
	n := countNewDistinctMatches(bootIniSectionRe, data, baseline)
	if n < 2 {
		return false, 0
	}
	return true, n
}

// --- Apache config -----------------------------------------------------------

// apacheDirectiveRe matches an Apache directive at line start with its argument.
// The former markers "ServerRoot"/"DocumentRoot" were anchorless words.
var apacheDirectiveRe = regexp.MustCompile(`(?im)^[ \t]*(ServerRoot[ \t]+\S|DocumentRoot[ \t]+\S|Listen[ \t]+\d|<VirtualHost\b|<Directory\b|LoadModule[ \t]+\S|ErrorLog[ \t]+\S|CustomLog[ \t]+\S|ServerName[ \t]+\S|DirectoryIndex[ \t]+\S)`)

// ConfirmApacheConf confirms a leaked Apache config by two distinct directives.
func ConfirmApacheConf(data, baseline string) (bool, int) {
	n := countNewDistinctMatches(apacheDirectiveRe, data, baseline)
	if n < 2 {
		return false, 0
	}
	return true, n
}

// --- Nginx config ------------------------------------------------------------

// nginxDirectiveRe matches an nginx directive at line start with its value /
// block brace. The former markers "server"/"location" were anchorless words
// that matched the cf-beacon JSON keys "server_timing"/"location_startswith" on
// a Cloudflare block page — this requires `server {` / `location /…`, never a
// JSON key.
var nginxDirectiveRe = regexp.MustCompile(`(?im)^[ \t]*(worker_processes[ \t]+\S|worker_connections[ \t]+\d|events[ \t]*\{|http[ \t]*\{|server[ \t]*\{|listen[ \t]+[\d\[]|server_name[ \t]+\S|location[ \t]+[~/=@^]|proxy_pass[ \t]+\S|fastcgi_pass[ \t]+\S|upstream[ \t]+\S|access_log[ \t]+\S|error_log[ \t]+\S|sendfile[ \t]+(on|off)|keepalive_timeout[ \t]+\d|include[ \t]+\S)`)

// ConfirmNginxConf confirms a leaked nginx config by two distinct directives.
func ConfirmNginxConf(data, baseline string) (bool, int) {
	n := countNewDistinctMatches(nginxDirectiveRe, data, baseline)
	if n < 2 {
		return false, 0
	}
	return true, n
}

// --- Java web.xml ------------------------------------------------------------

var webXMLOpenRe = regexp.MustCompile(`(?i)<web-app[\s>]`)
var webXMLCloseRe = regexp.MustCompile(`(?i)</web-app>`)

// ConfirmWebXML confirms a leaked web.xml by its open+close root element.
func ConfirmWebXML(data, baseline string) (bool, int) {
	if hasNewMatch(webXMLOpenRe, data, baseline) && webXMLCloseRe.MatchString(data) {
		return true, 2
	}
	return false, 0
}

// --- Git directory -----------------------------------------------------------

// gitHeadRe matches the symbolic-ref line that a .git/HEAD always carries.
var gitHeadRe = regexp.MustCompile(`(?m)^ref:[ \t]*refs/(heads|tags|remotes)/`)

// ConfirmGitHead confirms a leaked .git/HEAD by its symbolic-ref line.
func ConfirmGitHead(data, baseline string) (bool, int) {
	if hasNewMatch(gitHeadRe, data, baseline) {
		return true, 2
	}
	return false, 0
}

// --- Application .env --------------------------------------------------------

// dotenvAssignRe matches a sensitive KEY=VALUE assignment with a non-empty value
// at line start. Requiring the assignment shape — not the bare key word — keeps
// prose or JSON that merely mentions DB_PASSWORD from confirming.
var dotenvAssignRe = regexp.MustCompile(`(?im)^[ \t]*(DB_PASSWORD|DB_USERNAME|DB_DATABASE|DB_HOST|DB_CONNECTION|APP_KEY|APP_SECRET|APP_ENV|APP_DEBUG|MAIL_PASSWORD|REDIS_PASSWORD|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|SECRET_KEY|JWT_SECRET|STRIPE_SECRET)[ \t]*=[ \t]*\S`)

// ConfirmDotenv confirms a leaked .env by two distinct sensitive assignments.
func ConfirmDotenv(data, baseline string) (bool, int) {
	n := countNewDistinctMatches(dotenvAssignRe, data, baseline)
	if n < 2 {
		return false, 0
	}
	return true, n
}

// --- .htpasswd ---------------------------------------------------------------

var htpasswdLineRe = regexp.MustCompile(`(?m)^[A-Za-z0-9._-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$1\$|\$5\$|\$6\$)`)

// ConfirmHtpasswd confirms a leaked .htpasswd by a hashed credential line.
func ConfirmHtpasswd(data, baseline string) (bool, int) {
	n := countNewDistinctMatches(htpasswdLineRe, data, baseline)
	if n < 1 {
		return false, 0
	}
	return true, n + 2
}

// --- Access logs -------------------------------------------------------------

// accessLogLineRe matches a combined/common-log-format line: leading IP, the
// bracketed timestamp, then a quoted request line. Requiring the full shape (not
// a bare `GET `/`HTTP/1.`) keeps it from firing on any page that echoes a method.
var accessLogLineRe = regexp.MustCompile(`(?m)^\S+ \S+ \S+ \[[^\]]+\] "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^"]*HTTP/\d`)

// ConfirmAccessLog confirms a leaked access log by two distinct request lines.
func ConfirmAccessLog(data, baseline string) (bool, int) {
	n := countNewDistinctMatches(accessLogLineRe, data, baseline)
	if n < 2 {
		return false, 0
	}
	return true, n
}

// --- shared corroboration primitives -----------------------------------------

// hasNewMatch reports whether re matches data on a substring that is not already
// present verbatim in baseline (so the evidence is attacker-induced).
func hasNewMatch(re *regexp.Regexp, data, baseline string) bool {
	for _, m := range re.FindAllString(data, -1) {
		if baseline != "" && strings.Contains(baseline, m) {
			continue
		}
		return true
	}
	return false
}

// countNewDistinctMatches counts the distinct (case-insensitive) substrings re
// matches in data that are not already present verbatim in baseline — "the
// file's own lines appeared, and they weren't there before we fuzzed".
func countNewDistinctMatches(re *regexp.Regexp, data, baseline string) int {
	seen := make(map[string]struct{})
	for _, m := range re.FindAllString(data, -1) {
		if baseline != "" && strings.Contains(baseline, m) {
			continue
		}
		seen[strings.ToLower(strings.TrimSpace(m))] = struct{}{}
	}
	return len(seen)
}
