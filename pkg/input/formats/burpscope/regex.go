package burpscope

import (
	"strings"
	"unicode"
)

// Burp writes advanced-mode scope rules as regexes ("^www\.example\.com$"),
// not as hostnames. To turn a rule back into something scannable we need the
// plain text a pattern matches — which only exists when the pattern is fully
// literal. The helpers below extract that text and report when they cannot,
// so a wildcard rule is skipped loudly rather than guessed at.

// metaChars are the regex operators that end a literal run.
const metaChars = `.+*?()[]{}|^$`

func isMeta(r rune) bool { return strings.ContainsRune(metaChars, r) }

// isQuantifier reports whether r quantifies the atom before it. A quantifier
// means the preceding character is optional/repeated, so it is not part of the
// literal prefix — "/ab c*" matches "/ab", not "/abc".
func isQuantifier(r rune) bool { return r == '*' || r == '+' || r == '?' || r == '{' }

// isLiteralEscape reports whether `\r` stands for the character r itself
// (`\.`, `\-`, `\/`) rather than a character class (`\d`, `\w`, `\b`).
func isLiteralEscape(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }

// scanLiteral walks pattern and returns the leading run of characters that
// match themselves, plus whether the entire pattern was consumed.
func scanLiteral(pattern string) (string, bool) {
	var b strings.Builder
	rs := []rune(pattern)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '\\':
			if i+1 >= len(rs) || !isLiteralEscape(rs[i+1]) {
				return b.String(), false
			}
			// An escaped atom can still be quantified ("\.*"), in which case it
			// is not part of the literal.
			if i+2 < len(rs) && isQuantifier(rs[i+2]) {
				return b.String(), false
			}
			b.WriteRune(rs[i+1])
			i++
		case isMeta(c):
			return b.String(), false
		default:
			if i+1 < len(rs) && isQuantifier(rs[i+1]) {
				return b.String(), false
			}
			b.WriteRune(c)
		}
	}
	return b.String(), true
}

// trimAnchors strips the inline case-insensitivity flag and the ^/$ anchors
// Burp puts on every generated rule. A trailing `\$` is a literal dollar sign,
// not an anchor.
func trimAnchors(pattern string) string {
	pattern = strings.TrimPrefix(strings.TrimSpace(pattern), "(?i)")
	pattern = strings.TrimPrefix(pattern, "^")
	if strings.HasSuffix(pattern, "$") && !strings.HasSuffix(pattern, `\$`) {
		pattern = strings.TrimSuffix(pattern, "$")
	}
	return pattern
}

// literalPattern returns the exact string a fully-literal pattern matches.
// ok is false for anything containing an operator — "^.*\.example\.com$" has
// no single value and cannot become a target URL.
func literalPattern(pattern string) (string, bool) {
	lit, complete := scanLiteral(trimAnchors(pattern))
	if !complete || lit == "" {
		return "", false
	}
	return lit, true
}

// literalPathPrefix returns the fixed leading path a Burp `file` regex pins.
// Unlike literalPattern this is best-effort: "^/api/.*" is not literal, but
// "/api/" is a usable seed path. Anything without a usable prefix falls back
// to "/".
func literalPathPrefix(pattern string) string {
	lit, _ := scanLiteral(trimAnchors(pattern))
	if !strings.HasPrefix(lit, "/") {
		return "/"
	}
	return lit
}

// displayPattern renders a host regex in the shorthand a human wrote it as, so
// a skipped wildcard rule is reported as "*.example.com" rather than
// "^.*\.example\.com$".
func displayPattern(pattern string) string {
	p := trimAnchors(pattern)
	p = strings.ReplaceAll(p, `\.`, ".")
	p = strings.ReplaceAll(p, `\-`, "-")
	p = strings.ReplaceAll(p, ".*", "*")
	return p
}
