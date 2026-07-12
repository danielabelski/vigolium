package secret_detect

import "strings"

// IsValueShapeNoise reports whether a matched secret VALUE is a structural false
// positive by its shape alone. The first three shapes are caught regardless of
// which rule matched; the rest are scoped to the generic-credential rule family:
//
//   - A Google reCAPTCHA site key (6L… 40 chars) matched by a rule that is NOT
//     the reCAPTCHA rule — the public widget key mis-attributed as some other
//     provider's secret (e.g. a generic rule firing on a `data-sitekey` value).
//     A correctly-attributed reCAPTCHA match is handled by the severity layer
//     (Info), not dropped here.
//   - A code/markup fragment rather than a credential token — the captured value
//     carries a character that never appears inside a real credential
//     (whitespace, an HTML angle bracket, a JS/JSON brace, a quote, a backtick, a
//     parenthesis, a square bracket, a pipe, or a backslash). This is the dominant
//     shape of the low-confidence generic-rule captures, e.g. `":"1234"}</li>` from
//     a "Generic Username and Password" match on page markup, or a `],input[type=`
//     CSS-selector fragment.
//   - A hyphen-delimited CMS/asset resource slug mis-captured as a fixed-width API
//     key by a loose provider proximity rule — `Engineering-Kkk2cg-…-hero-block`
//     grabbed from an HTML `key-src="…"` attribute and graded a High IBM Cloud key
//     (see isHyphenatedResourceSlug).
//   - A source-code / UI identifier slug captured by a generic username/password
//     rule — a `-`/`_`-separated word-only identifier like `label-password` or
//     `label_username` grabbed from a compiled JS bundle's component metadata (see
//     isIdentifierSlug). Scoped to that rule family so it never second-guesses a
//     provider-specific rule's capture. A bare camelCase value (no separator) is
//     deliberately NOT dropped here — a letters-only camelCase string is as likely a
//     real weak password as a variable name (see isIdentifierSlug); the camelCase
//     field names that are noise spell out the keyword and fall to the check below.
//   - A dotted JS property-access path captured by a generic username/password
//     rule — `v.userRecordStr`, `v.translationObject.pageLabel` grabbed from a
//     framework component descriptor (e.g. Salesforce Aura's
//     {"exprType":"PROPERTY","path":"v.…"} beside a "…Password" target name). See
//     isDottedIdentifierPath. Same generic-family scope.
//   - A field-name / DOM-id keyword captured by a generic username/password rule —
//     an all-letters token that spells out the keyword itself, like
//     `currentpassword` from pOLD_PASSWORD_ELEM:"currentpassword". See
//     isCredentialKeywordName. Same generic-family scope.
//   - An i18n / CSS label-map pair (`forgot_password::We`) or a generated UI
//     resource id with a long numeric snowflake (`PASSWORD_21545675329847530_…`,
//     `gigya-dropdown-2641…`), captured by a generic username/password rule. See
//     the `::` check and hasLongDigitRunSegment. Same generic-family scope.
//
// Callers apply this ONLY to untrusted-tier matches (medium/low-confidence
// rules): the curated high-confidence rules are anchored tightly enough that
// their captures are trusted verbatim and never second-guessed by value shape.
//
// A plain hex digest is deliberately NOT treated as noise: real provider secrets
// (Mailgun, Weights & Biases, …) are fixed-width hex, and the webpack
// content-hash-manifest case is already dropped by IsChunkHashManifestMatch.
func IsValueShapeNoise(ruleID, ruleName, secret string) bool {
	s := strings.TrimSpace(secret)
	if s == "" {
		return false
	}
	if !IsReCaptchaSiteKey(ruleName) && isReCaptchaSiteKeyShape(s) {
		return true
	}
	if hasNonCredentialChar(s) {
		return true
	}
	// A hyphen-delimited CMS/asset slug mis-captured as a fixed-width key by a loose
	// provider proximity rule (IBM Cloud's `bx|ibm … KEY … [0-9A-Z_-]{42,44}` firing
	// on an HTML `key-src="Engineering-…-hero-block"` attribute). Rule-agnostic: this
	// shape is never a real credential regardless of which rule attributed it.
	if isHyphenatedResourceSlug(s) {
		return true
	}
	// The generic username/password proximity rules capture whatever token sits
	// near a user/password keyword. Inside a compiled JS bundle that is routinely
	// code rather than a credential: a source/UI identifier slug (a Stencil
	// `label-password` attribute name or a `passwordConfirm` prop), a dotted
	// property-access path from a framework component descriptor (Salesforce Aura's
	// `v.userRecordStr`), or the field's own keyword name (`currentpassword`). Drop
	// all three, but only for that generic-credential family: other rules keep
	// their captures verbatim.
	//
	// The capture frequently carries a leading/trailing JS structural delimiter the
	// tokenizer left attached — an object-key colon (`skipUserInfo:`) or a
	// string-escape backslash (`emailLabelChangeRedColor\`). Strip edge punctuation
	// (never interior — a genuinely structured value like `user:pass@host` keeps its
	// `:`/`@` and so still fails every check below) and judge the bare core.
	if isGenericCredentialRule(ruleID, ruleName) {
		core := trimEdgePunct(s)
		if isIdentifierSlug(core) || isDottedIdentifierPath(core) || isCredentialKeywordName(core) {
			return true
		}
		// A bare UUID captured next to a token/id/key keyword is a correlation /
		// request / session id (MSAL client-request-id, an analytics id), not a
		// credential — the generic proximity rules grab these out of telemetry blobs.
		if isUUID(core) {
			return true
		}
		// i18n / CSS label maps serialise as `key::Value` pairs (`forgot_password::We`,
		// `db-oldpw::Password`); a `::` never appears inside a real credential.
		if strings.Contains(core, "::") {
			return true
		}
		// Generated UI resource ids embed a long numeric snowflake between word
		// segments — `PASSWORD_21545675329847530_HIDE_TITLE`, `gigya-dropdown-2641…`.
		// No credential carries an underscore/hyphen-delimited pure-digit run that
		// long, so this is a component id, not a secret.
		if hasLongDigitRunSegment(core) {
			return true
		}
	}
	return false
}

// hasLongDigitRunSegment reports whether s has a '_' or '-' delimited segment that
// is a run of 8+ decimal digits — the snowflake/timestamp id a UI framework bakes
// into a generated resource key (SAP CDC's `PASSWORD_<19 digits>_…`, a
// `gigya-dropdown-<17 digits>`). Real credentials carry no such delimited pure-digit
// run, so within the generic-credential family this marks a component id. Scans in
// place (no slice allocation) since it runs on the secret-scan hot path.
func hasLongDigitRunSegment(s string) bool {
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '_' && s[i] != '-' {
			continue
		}
		if seg := s[start:i]; len(seg) >= 8 {
			if hasLetter, hasDigit, hasOther := segClass(seg); hasDigit && !hasLetter && !hasOther {
				return true
			}
		}
		start = i + 1
	}
	return false
}

// segClass classifies a byte segment in one pass: whether it holds any ASCII letter,
// any ASCII digit, and any other byte. Shared by the '-'/'_'-delimited segment scans.
func segClass(seg string) (hasLetter, hasDigit, hasOther bool) {
	for i := 0; i < len(seg); i++ {
		switch c := seg[i]; {
		case isLetterByte(c):
			hasLetter = true
		case isDigitByte(c):
			hasDigit = true
		default:
			hasOther = true
		}
	}
	return
}

// trimEdgePunct removes leading and trailing runs of non-identifier characters,
// leaving a core of [A-Za-z0-9_$] with any interior punctuation (a dotted path's
// `.`, a structured value's `:`/`@`/`/`) intact. It normalises the generic
// proximity rules' habit of capturing a bare code identifier with a dangling JS
// delimiter — `skipUserInfo:`, `emailLabelChangeRedColor\`, `"path":"v.foo"` → so
// the slug / dotted-path / keyword checks see the identifier, not the delimiter.
func trimEdgePunct(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		// Trim any non-identifier byte; every non-ASCII rune is also an edge to trim.
		return r >= 0x80 || !isIdentByte(byte(r))
	})
}

// isGenericCredentialRule reports whether a rule is one of the low-confidence
// proximity heuristics that grab the token adjacent to a user/password/credential
// keyword — the rules prone to capturing a neighbouring code/markup identifier, so
// the identifier-slug guards apply to them alone.
//
// The vigolium generic namespace is entirely credential-proximity rules, so its
// stable ID prefix (vigoliumGenericRuleIDPrefix — the same prefix IsGenericSecretRule
// bundles on) scopes the guards: a future vigolium.generic.* rule inherits them for
// free, with no name to keep in sync. The kingfisher side must stay a by-name match:
// its generic.* namespace is broader than this proximity subset — generic.1/.2 are
// opaque-token rules whose captures must be kept verbatim — so only the two proximity
// rules "Generic Username and Password" (kingfisher.generic.3/.4) and "Generic
// Password" (.5) are named here.
func isGenericCredentialRule(ruleID, ruleName string) bool {
	if strings.HasPrefix(ruleID, vigoliumGenericRuleIDPrefix) {
		return true
	}
	switch ruleName {
	case "Generic Username and Password", "Generic Password":
		return true
	}
	return false
}

// isIdentifierSlug reports whether s is a source-code / UI identifier — pure-letter
// word segments joined by an EXPLICIT `-` or `_` separator, carrying no digits or
// other entropy — rather than a credential value. These are the dominant capture
// of the generic username/password proximity rules when they fire inside a
// minified web-component bundle, e.g. `label-password`, `label-unmatched-passwords`,
// and `label_username`.
//
// Only an explicit `-`/`_` separator marks a slug. A bare camelCase word with no
// separator (`IamUsedForTesting`, `SuperSecretPass`, `AdminUser`) is NOT treated as
// an identifier here: a letters-only camelCase string is just as plausibly a real —
// if weak — credential value as a variable name, and silently dropping it loses
// genuine leaks (JuiceShop ships `testingPassword="IamUsedForTesting"` in main.js,
// which the old camelCase-boundary branch suppressed). The camelCase field *names*
// that genuinely are noise — `passwordConfirm`, `oldPassword`, `labelUsername` —
// spell out the credential keyword itself and are caught by isCredentialKeywordName
// instead; whatever letters-only camelCase value slips past both is surfaced only at
// the low-signal Suspect tier (and folded into the per-host suspect bundle), so the
// recovery costs a little Suspect noise, never a High-severity false positive.
//
// Requiring a pure-letter body keeps the guard off real tokens: any digit or symbol
// (`hunter2`, `P@ssw0rd`, an opaque key) fails the letter-only check, and a single
// unbroken word (`admin`, `correcthorsebattery`) has no separator — so all of those
// are left untouched.
func isIdentifierSlug(s string) bool {
	sawSeparator := false // an explicit '-' or '_' word separator
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' || c == '_':
			sawSeparator = true
		case isLetterByte(c):
			// a letter — part of a word segment
		default:
			// a digit or any other character means this carries entropy /
			// structure a plain word identifier never has — not a slug.
			return false
		}
	}
	return sawSeparator
}

// isDottedIdentifierPath reports whether s is a chain of JS identifiers joined by
// '.', i.e. a property-access expression like `v.userRecordStr` or
// `v.translationObject.pageLabel`. The generic username/password proximity rules
// capture these out of framework component descriptors — e.g. Salesforce Aura
// serialises attribute bindings as {"exprType":"PROPERTY","path":"v.userRecordStr"}
// which routinely sit within 16 chars of a "…Password" component/target name, so
// the "Generic Password" rule grabs the quoted path. A real credential is never a
// dotted chain of bare identifiers (JWTs are base64 segments, connection strings
// carry `://`/`@`), so within the generic-credential family this shape is code.
//
// Each dot-separated segment must be a word-only identifier — letters, '_' or '$',
// NO digits (see isWordSegment). Excluding digits is deliberate: it rejects version
// strings and dotted IPs (`1.5.3`, `10.0.0.1`) AND, more importantly, keeps a
// dotted base64 token (a JWT's `header.payload.signature`, whose segments are
// digit-bearing base64) from ever reading as a code path — so a real dotted secret
// is never mistaken for a framework property access.
func isDottedIdentifierPath(s string) bool {
	// Walk the '.'-delimited segments in place (no slice allocation on the hot path);
	// every segment must be a word-only identifier and there must be at least two.
	segCount, start := 0, 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			continue
		}
		if !isWordSegment(s[start:i]) {
			return false
		}
		segCount++
		start = i + 1
	}
	return segCount >= 2
}

// isWordSegment reports whether seg is a non-empty run of letters, '_' or '$' —
// a word-like identifier segment carrying no digits. Empty is not a segment (so a
// leading/trailing/doubled dot in a path fails the caller).
func isWordSegment(seg string) bool {
	if seg == "" {
		return false
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if !isLetterByte(c) && c != '_' && c != '$' {
			return false
		}
	}
	return true
}

// isCredentialKeywordName reports whether s is an all-letters token that spells
// out a credential keyword — "password", "passwd", or "username". A value captured
// by a user/password proximity rule that itself contains one of these words is the
// field's name / DOM id / label, not the credential it names: `currentpassword`
// from pOLD_PASSWORD_ELEM:"currentpassword", `oldPassword`, `confirmUsername`. The
// all-letters guard keeps the scope tight — a value carrying a digit or symbol
// (`password123`, `P@ssw0rd_backup`) is left to the weak-password rule and the
// other guards rather than dropped here.
func isCredentialKeywordName(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isLetterByte(s[i]) {
			return false
		}
	}
	l := strings.ToLower(s)
	return strings.Contains(l, "password") ||
		strings.Contains(l, "passwd") ||
		strings.Contains(l, "username")
}

// isHyphenatedResourceSlug reports whether s is a hyphen-delimited resource slug —
// a CMS/asset identifier that interleaves dictionary words with random-looking
// mixed-alphanumeric id segments, e.g. `Engineering-Kkk2cg-yaC5K7-5LlHtk-ph-hero-block`
// lifted from an HTML `key-src="…"` attribute. A loose provider proximity rule (IBM
// Cloud's `bx|ibm … KEY … [0-9A-Z_-]{42,44}`) grabs one as a fake 44-char API key
// and — being a named provider family — grades it High.
//
// It is distinguished from a genuinely hyphenated secret by requiring ALL of: 4+
// hyphen segments, 2+ pure-letter word segments (len ≥ 3), and 1+ mixed
// letters-and-digits segment. A UUID's segments are all hex (no pure-letter word);
// a diceware `correct-horse-battery-staple` has no mixed alnum segment; a real
// prefixed key (`sk-proj-<one long blob>`) splits into ≤3 segments — so none trip
// this. A segment carrying any non-alphanumeric byte is ignored for the counts.
func isHyphenatedResourceSlug(s string) bool {
	// Walk the '-'-delimited segments in place — this runs on every untrusted match,
	// so it must not allocate. Count total segments, pure-letter word segments, and
	// mixed letters-and-digits segments; a segment with any other byte is ignored.
	segCount, wordSegs, mixedSegs, start := 0, 0, 0, 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '-' {
			continue
		}
		seg := s[start:i]
		start = i + 1
		segCount++
		hasLetter, hasDigit, hasOther := segClass(seg)
		if hasOther {
			continue
		}
		if hasLetter && !hasDigit && len(seg) >= 3 {
			wordSegs++
		}
		if hasLetter && hasDigit {
			mixedSegs++
		}
	}
	return segCount >= 4 && wordSegs >= 2 && mixedSegs >= 1
}

// isUUID reports whether s is a canonical 8-4-4-4-12 hexadecimal UUID. Within the
// generic-credential family a UUID-shaped capture is an id (correlation, request,
// session, resource), not a secret, so it is dropped; a provider-specific rule that
// legitimately captures a UUID secret never reaches this guard.
func isUUID(s string) bool {
	// Sub-slicing a string does not allocate, so this stays on the hot path while
	// reusing the vetted hex classifier for the four fixed-width hex spans.
	return len(s) == 36 &&
		s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' &&
		isHexRun(s[0:8]) && isHexRun(s[9:13]) && isHexRun(s[14:18]) &&
		isHexRun(s[19:23]) && isHexRun(s[24:36])
}

// isReCaptchaSiteKeyShape reports whether s has the Google reCAPTCHA site-key
// shape: the literal prefix "6L" followed by 38 URL-safe-base64 characters
// (40 total). Both reCAPTCHA v2 and v3 site keys use this format.
func isReCaptchaSiteKeyShape(s string) bool {
	if len(s) != 40 || s[0] != '6' || s[1] != 'L' {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// hasNonCredentialChar reports whether s contains a character that never appears
// inside a real credential token. The credential formats in scope — API keys,
// base64/JWT tokens, connection strings, URIs — use only [A-Za-z0-9] plus a
// small punctuation set (_ - . / + = : @ ~ % # & ? and base64 padding), so any
// whitespace or markup/code structural character below signals a code/markup
// capture rather than a secret. Brackets, pipe, and backslash join the original
// markup set: none appear in a credential/base64/connection-string value, but they
// pervade the CSS selectors (`],input[type=`), JS operators (`a||b`), and escaped
// string literals (`Forgot\x20password`) the generic rules capture. The set stays
// conservative on `;`, `=`, `,`, `:` — excluded because connection strings and
// base64 padding use them, so they are not reliable non-credential signals.
func hasNonCredentialChar(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r', '<', '>', '{', '}', '"', '\'', '`', '(', ')', '[', ']', '|', '\\':
			return true
		}
	}
	return false
}
