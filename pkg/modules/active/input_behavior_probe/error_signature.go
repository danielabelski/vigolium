package input_behavior_probe

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// maxErrorScanBytes caps how much of a 5xx body bodyLeaksServerError inspects.
// A leaked stack trace / debug banner surfaces at the top of the body, so a large
// error payload cannot hide a match past this window — but it can't blow up the
// regex scan on a pathological body either.
const maxErrorScanBytes = 65536

// serverErrorDisclosurePatterns match genuine application-level error DISCLOSURE in
// a 5xx body: a stack trace, a framework/language exception, a database error, or a
// debug page. A →5xx that carries one of these is a real input-handling lead — the
// app tried to process the input and leaked how it failed. Deliberately EXCLUDED are
// generic edge/decoder phrases ("Internal Server Error", "URI malformed", "Bad
// Request", empty bodies): those are the CDN / reverse proxy / URL decoder rejecting
// malformed input (a bad %-escape, a garbage forwarding header) BEFORE the app runs.
// That rejection is deterministic and fires on essentially every Node/Express/CDN-
// fronted host, and was the dominant false positive this probe used to report.
var serverErrorDisclosurePatterns = []*regexp.Regexp{
	// Java / JVM
	regexp.MustCompile(`(?i)at [\w.$]+\([\w]+\.java:\d+\)`),
	regexp.MustCompile(`(?i)\b(?:java|javax)\.[a-z.]+\.[A-Z]\w*(?:Exception|Error)\b`),
	regexp.MustCompile(`(?i)org\.springframework\.[\w.]+(?:Exception|Error)`),
	// Python
	regexp.MustCompile(`(?i)Traceback \(most recent call last\)`),
	regexp.MustCompile(`(?i)File "[^"]+\.py", line \d+`),
	// Node.js / JavaScript: an uncaught error type, or a real file:line:col frame
	regexp.MustCompile(`(?i)at [\w.<>$\[\] ]+ \([^)]+\.(?:js|ts|mjs|cjs):\d+:\d+\)`),
	regexp.MustCompile(`(?:TypeError|ReferenceError|SyntaxError|RangeError|EvalError): \S`),
	// PHP
	regexp.MustCompile(`(?i)PHP (?:Warning|Error|Notice|Fatal error|Parse error):`),
	regexp.MustCompile(`(?i)Fatal error:.*on line \d+`),
	regexp.MustCompile(`(?i)Stack trace:\s*#\d+`),
	// .NET / C#
	regexp.MustCompile(`(?i)at [\w.<>]+\([^)]*\) in [^:\n]+:\s*line \d+`),
	regexp.MustCompile(`(?i)System\.\w+Exception\b`),
	// Ruby (backtick built via concat so the raw string stays readable)
	regexp.MustCompile(`(?i)/[\w./]+\.rb:\d+:in ` + "`" + `[\w?!]+'`),
	regexp.MustCompile(`(?i)(?:NoMethodError|NameError|ArgumentError|RuntimeError|StandardError): `),
	// Go
	regexp.MustCompile(`(?i)goroutine \d+ \[`),
	regexp.MustCompile(`\t[\w/.]+\.go:\d+`),
	regexp.MustCompile(`(?i)\bpanic: `),
	regexp.MustCompile(`(?i)runtime error:`),
	// A loose MySQL phrase kept local because the shared modkit catalog matches
	// the stricter "SQL syntax .*? MySQL" form; the full DBMS signature set —
	// including the Node.js SQLite/Sequelize format that hid the Juice Shop login
	// SQLi — is inherited via modkit.BodyHasSQLError in bodyLeaksServerError.
	regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
}

// serverErrorDisclosureKeywords are lowercase substrings that only appear in a
// leaked application error / debug page, never in a generic edge 5xx.
var serverErrorDisclosureKeywords = []string{
	"exception in thread",
	"unhandled exception",
	"nullpointerexception",
	"stackoverflowerror",
	"outofmemoryerror",
	"undefined index:",
	"undefined variable",
	"vendor/autoload.php",
	"/web-inf/",
	"django_settings_module",
	"werkzeug",
	"whoops, looks like something went wrong",
	"aspnetcore_environment",
}

// bodyLeaksServerError reports whether a 5xx body discloses a genuine application
// error (stack trace, framework/SQL exception, debug page) rather than a generic
// edge/decoder rejection. It gates the input-behavior probe's →5xx leg: a malformed-
// encoding probe (%ff / %00 / an invalid %-escape in the polyglot, or garbage in a
// forwarding header) that merely makes the CDN / URL decoder answer with a bland 500
// leaks nothing and must not be reported as an input-handling behavior change.
func bodyLeaksServerError(body string) bool {
	if body == "" {
		return false
	}
	if len(body) > maxErrorScanBytes {
		body = body[:maxErrorScanBytes]
	}
	lower := strings.ToLower(body)
	for _, kw := range serverErrorDisclosureKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	for _, re := range serverErrorDisclosurePatterns {
		if re.MatchString(body) {
			return true
		}
	}
	// Inherit the full shared DBMS error catalog (span-bounded to reject page
	// noise) so every backend signature — notably the Node.js SQLite/Sequelize
	// format — is recognized here without maintaining a second copy.
	return modkit.BodyHasSQLError(body)
}
