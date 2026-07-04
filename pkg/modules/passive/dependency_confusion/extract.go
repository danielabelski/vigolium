package dependency_confusion

import (
	"regexp"
	"strings"
)

// nodeBuiltins are Node.js core modules; they are never npm packages and would
// always 404, so they are dropped during normalization.
var nodeBuiltins = map[string]struct{}{
	"assert": {}, "async_hooks": {}, "buffer": {}, "child_process": {}, "cluster": {},
	"console": {}, "constants": {}, "crypto": {}, "dgram": {}, "diagnostics_channel": {},
	"dns": {}, "domain": {}, "events": {}, "fs": {}, "http": {}, "http2": {}, "https": {},
	"inspector": {}, "module": {}, "net": {}, "os": {}, "path": {}, "perf_hooks": {},
	"process": {}, "punycode": {}, "querystring": {}, "readline": {}, "repl": {},
	"stream": {}, "string_decoder": {}, "sys": {}, "timers": {}, "tls": {}, "trace_events": {},
	"tty": {}, "url": {}, "util": {}, "v8": {}, "vm": {}, "wasi": {}, "worker_threads": {}, "zlib": {},
}

// knownPublicScopes are npm scopes that are unambiguously public and maintained.
// This is a query-count optimization, NOT a correctness gate: names under these
// scopes resolve to HTTP 200 and would be classified "claimed" (and skipped)
// anyway. Dropping them before the network call just avoids hammering
// registry.npmjs.org with lookups whose answer we already know. The list is
// intentionally conservative and need not be exhaustive — an unlisted public
// scope simply costs one extra (still-capped) lookup.
var knownPublicScopes = map[string]struct{}{
	"@babel": {}, "@types": {}, "@angular": {}, "@angular-devkit": {}, "@vue": {},
	"@vitejs": {}, "@vercel": {}, "@next": {}, "@remix-run": {}, "@sveltejs": {},
	"@nestjs": {}, "@emotion": {}, "@mui": {}, "@material-ui": {}, "@reduxjs": {},
	"@tanstack": {}, "@storybook": {}, "@nrwl": {}, "@nx": {}, "@swc": {}, "@esbuild": {},
	"@rollup": {}, "@eslint": {}, "@typescript-eslint": {}, "@testing-library": {},
	"@sentry": {}, "@aws-sdk": {}, "@aws-crypto": {}, "@azure": {}, "@google-cloud": {},
	"@firebase": {}, "@apollo": {}, "@graphql-tools": {}, "@fortawesome": {}, "@radix-ui": {},
	"@headlessui": {}, "@heroicons": {}, "@floating-ui": {}, "@popperjs": {}, "@tiptap": {},
	"@octokit": {}, "@stripe": {}, "@okta": {}, "@auth0": {}, "@clerk": {}, "@supabase": {},
	"@prisma": {}, "@trpc": {}, "@tailwindcss": {}, "@capacitor": {}, "@ionic": {},
	"@expo": {}, "@react-navigation": {}, "@react-native": {}, "@react-native-community": {},
	"@shopify": {}, "@segment": {}, "@datadog": {}, "@opentelemetry": {}, "@grpc": {},
	"@protobufjs": {}, "@bufbuild": {}, "@connectrpc": {}, "@cloudflare": {}, "@netlify": {},
	"@ampproject": {}, "@rushstack": {}, "@lit": {}, "@webcomponents": {}, "@ungap": {},
}

// packageNameRe validates an npm package name (scoped or unscoped). npm names are
// lowercase, ≤214 chars, and limited to url-safe characters plus @ and / for the
// scope separator.
var packageNameRe = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)

func isScoped(name string) bool { return strings.HasPrefix(name, "@") }

// scopeOf returns the "@scope" prefix of a scoped name, or "" for an unscoped one.
func scopeOf(name string) string {
	if !isScoped(name) {
		return ""
	}
	if slash := strings.IndexByte(name, '/'); slash > 0 {
		return name[:slash]
	}
	return ""
}

// isKnownPublicScope reports whether name lives under a scope we treat as public.
func isKnownPublicScope(name string) bool {
	_, ok := knownPublicScopes[scopeOf(name)]
	return ok
}

// isValidPackageName reports whether name is a plausible npm package name.
func isValidPackageName(name string) bool {
	if name == "" || len(name) > 214 {
		return false
	}
	if !isScoped(name) {
		if _, ok := nodeBuiltins[name]; ok {
			return false
		}
	}
	return packageNameRe.MatchString(name)
}

// normalizePackageName reduces an import specifier to its bare package name
// (dropping subpaths and version ranges). It returns ok=false for relative paths,
// absolute URLs, node: builtins, and anything that is not a valid package name.
// Examples:
//
//	"@scope/name/sub/path" -> "@scope/name"
//	"left-pad/lib/x"       -> "left-pad"
//	"@scope/name@^1.2.0"   -> "@scope/name"
//	"./relative"           -> ("", false)
func normalizePackageName(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", false
	}
	// Relative and absolute paths, protocol URLs, and node: builtins are not
	// public npm dependencies.
	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "~") {
		return "", false
	}
	if strings.HasPrefix(spec, "node:") || strings.Contains(spec, "://") {
		return "", false
	}

	spec = stripVersion(spec)

	parts := strings.Split(spec, "/")
	var name string
	if isScoped(spec) {
		if len(parts) < 2 { // guards the parts[1] index below
			return "", false
		}
		name = parts[0] + "/" + parts[1] // "@scope/" survivors are dropped by isValidPackageName
	} else {
		name = parts[0]
	}

	if !isValidPackageName(name) {
		return "", false
	}
	return name, true
}

// stripVersion removes a trailing "@version" range from a spec, preserving the
// leading "@" of a scoped name. "@scope/name@^1.0.0" -> "@scope/name";
// "left-pad@1.0.0" -> "left-pad".
func stripVersion(spec string) string {
	at := strings.LastIndex(spec, "@")
	if at > 0 { // index 0 is the scope marker, not a version separator
		return spec[:at]
	}
	return spec
}

// bundleImportRe matches ES import/re-export sources, dynamic import(), and
// CommonJS require() specifiers in a JS bundle. The specifier is captured from
// whichever alternative fires (group 1 = static import/export, group 2 = dynamic
// import()/require()).
//
// Two guards keep it from matching the word "import"/"require" that merely
// appears inside a string literal or identifier (e.g. "@x/not-an-import"), which
// would otherwise swallow the following real import and manufacture junk names:
//   - a leading statement-boundary requirement, (?:^|[^\w.$-]), so the keyword
//     must be preceded by whitespace/;/{/(/,/= and not by an identifier char,
//     "-", or ".";
//   - the binding region before "from" is restricted to identifier/binding
//     characters [\w$*{},\s], so a match can never cross a quote or ";".
var bundleImportRe = regexp.MustCompile(
	`(?m)(?:^|[^\w.$-])(?:import|export)\s*(?:[\w$*{},\s]*?\bfrom\s*)?['"]([^'"]+)['"]` +
		`|(?:^|[^\w.$-])(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)`)

// extractScopedCandidates pulls the scoped (@org/name) package names worth a
// registry lookup out of a JavaScript response's import/require specifiers.
//
// It is deliberately narrow to avoid checking names that don't need checking:
//   - only scoped names (a bundle references many bare public packages; scoped
//     names are the classic dependency-confusion target and far less noisy);
//   - names under a known-public scope are dropped (they exist, so a lookup is
//     wasted and a stray 404 there would be a typo, not a confusion candidate);
//   - only syntactically valid package names survive, so minified junk and
//     non-module string literals never reach the registry.
//
// Order is unspecified: FlushFindings sorts before querying, so intra-response
// order is never observed.
func extractScopedCandidates(body string) []string {
	var names []string
	seen := map[string]struct{}{}
	for _, m := range bundleImportRe.FindAllStringSubmatch(body, -1) {
		spec := m[1]
		if spec == "" {
			spec = m[2]
		}
		if !strings.HasPrefix(strings.TrimSpace(spec), "@") {
			continue
		}
		n, ok := normalizePackageName(spec)
		if !ok || !isScoped(n) || isKnownPublicScope(n) {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		names = append(names, n)
	}
	return names
}
