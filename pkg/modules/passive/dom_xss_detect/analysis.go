package dom_xss_detect

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// TODO: this accepts '$' in identifiers, so jQuery-flavoured names like `$el`
	// are recorded as tainted — but containsWordBounded can never match them,
	// because '$' is not an ASCII word character and the `\b` semantics it
	// reproduces require a word character on the outside. That whole identifier
	// family is a silent gap in taint propagation. Closing it is a detection
	// change, not a refactor, so it needs its own FP assessment.
	assignmentRe = regexp.MustCompile(`(?s)^\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+)$`)
	sanitizerRe  = regexp.MustCompile(`(?i)\b(?:DOMPurify\.sanitize|sanitizeHTML|escapeHTML|encodeURIComponent|htmlEncode)\s*\(`)
)

// analyseOpenRedirect reports only a traced source-to-navigation flow. Merely
// having location.search and location.href somewhere in the same script is not
// evidence that attacker-controlled data reaches the redirect.
func analyseOpenRedirect(response string) string {
	flow := analyseFlows(response, openRedirectSinks)
	if flow == "" {
		return ""
	}
	return "Traced controllable data into redirect sink:\n" + flow
}

// analyse reports a DOM-XSS candidate only when the lightweight tracer can
// connect a browser-controlled source to an executable DOM sink. The previous
// implementation returned a finding when either a source or a sink appeared,
// which turned ordinary source reads and ordinary DOM rendering into findings.
func analyse(response string) string {
	return analyseFlows(response, sinks)
}

// analyseFlows performs deliberately conservative, statement-local taint
// propagation for inline scripts. It understands direct source-to-sink calls
// and simple identifier assignments/aliases. Complex JavaScript is left to the
// dedicated dom_xss_taint analyzer rather than guessed here.
func analyseFlows(response string, sinkRe *regexp.Regexp) string {
	scripts := scriptExtract.FindAllStringSubmatch(response, -1)
	var flows []string
	for _, script := range scripts {
		if len(script) < 2 {
			continue
		}
		tainted := make(map[string]struct{})
		for lineIndex, line := range strings.Split(script[1], "\n") {
			for _, statement := range splitStatements(line) {
				statement = strings.TrimSpace(statement)
				if statement == "" {
					continue
				}

				// Gate on the sink first. Every term is a pure predicate, so the
				// order does not change the result — but most statements are not
				// sinks, and the taint check is the expensive one.
				if sinkRe.MatchString(statement) && !sanitizerRe.MatchString(statement) {
					flowValue := assignmentValue(statement)
					if sources.MatchString(flowValue) || statementUsesTainted(flowValue, tainted) {
						flows = append(flows, fmt.Sprintf("%-3d %s", lineIndex+1, statement))
					}
				}

				match := assignmentRe.FindStringSubmatch(statement)
				if len(match) != 3 {
					continue
				}
				name, rhs := match[1], match[2]
				if sanitizerRe.MatchString(rhs) {
					delete(tainted, name)
					continue
				}
				if sources.MatchString(rhs) || statementUsesTainted(rhs, tainted) {
					tainted[name] = struct{}{}
				} else {
					delete(tainted, name)
				}
			}
		}
	}
	return strings.Join(flows, "\n")
}

// assignmentValue returns the value side of a simple JavaScript assignment.
// This is important for navigation: in `location.href = "/home"`, location.href
// is a sink being written, not an attacker-controlled source being read.
func assignmentValue(statement string) string {
	for i := 0; i < len(statement); i++ {
		if statement[i] != '=' {
			continue
		}
		var prev, next byte
		if i > 0 {
			prev = statement[i-1]
		}
		if i+1 < len(statement) {
			next = statement[i+1]
		}
		if prev == '=' || prev == '!' || prev == '<' || prev == '>' || next == '=' || next == '>' {
			continue
		}
		return statement[i+1:]
	}
	return statement
}

func splitStatements(line string) []string {
	// This light detector intentionally handles only straight-line statements.
	// Keeping braces with their statement preserves enough context for sink/source
	// regexes while avoiding the old whole-script co-occurrence oracle.
	return strings.FieldsFunc(line, func(r rune) bool { return r == ';' })
}

// statementUsesTainted reports whether statement references any tainted
// identifier as a whole word.
//
// This is a direct scan rather than a regex on purpose. The obvious spelling —
// compiling `\b<name>\b` per tainted name — compiles a fresh regex for every
// (statement, tainted name) pair, and the caller invokes this twice per
// statement, so cost is statements × tainted names × compilation. On a
// JS-heavy response that is hundreds of thousands of compilations: measured at
// ~50 µs and 47 KB allocated per call with 20 tainted names, versus ~0.9 µs and
// zero allocations here.
//
// containsWordBounded reproduces the previous `\b` semantics exactly, including
// for names containing '$' — see its doc comment.
func statementUsesTainted(statement string, tainted map[string]struct{}) bool {
	for name := range tainted {
		if containsWordBounded(statement, name) {
			return true
		}
	}
	return false
}

// isWordByte reports whether b is an ASCII word character, i.e. the [0-9A-Za-z_]
// class Go's regexp `\b` is defined against. '$' is deliberately NOT a word
// character here, because it is not one for `\b` either.
func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z')
}

// containsWordBounded reports whether name occurs in s at a position where
// `\b` + name + `\b` would have matched.
//
// `\b` asserts a word/non-word transition, so whether it requires a word or a
// non-word neighbour depends on the adjacent character OF THE NAME. That matters
// here because JavaScript identifiers may contain '$', which is not an ASCII word
// character: for a name like "$el" the leading `\b` sits between two non-word
// characters at the start of a statement and therefore never matched — a quirk of
// the original regex that this function preserves rather than quietly fixes.
// Treating '$' as a word character would start tracing taint through jQuery-style
// identifiers that were previously ignored, which is a detection change, not a
// performance change, and does not belong in this refactor.
func containsWordBounded(s, name string) bool {
	if name == "" || len(name) > len(s) {
		return false
	}

	nameStartsWord := isWordByte(name[0])
	nameEndsWord := isWordByte(name[len(name)-1])

	for offset := 0; ; {
		idx := strings.Index(s[offset:], name)
		if idx < 0 {
			return false
		}
		start := offset + idx
		end := start + len(name)

		// A boundary exists where exactly one side is a word character.
		leftIsWord := start > 0 && isWordByte(s[start-1])
		rightIsWord := end < len(s) && isWordByte(s[end])

		if leftIsWord != nameStartsWord && rightIsWord != nameEndsWord {
			return true
		}
		offset = start + 1
	}
}
