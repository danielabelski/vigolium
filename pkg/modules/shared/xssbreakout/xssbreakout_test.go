package xssbreakout

import (
	"strings"
	"testing"
)

func TestJSStringPayloads_SingleQuote(t *testing.T) {
	alert := "alert(`vigx1234`)"
	got := JSStringPayloads('\'', alert)

	if len(got) != 5 {
		t.Fatalf("expected 5 payloads, got %d: %v", len(got), got)
	}

	// The operator-chaining variants are what let this confirm an expression-context
	// reflection where a statement terminator would SyntaxError.
	wantOps := []string{
		"'^" + alert + "^'",
		"'-" + alert + "-'",
	}
	for _, w := range wantOps {
		if !containsExact(got, w) {
			t.Errorf("missing operator-chaining payload %q in %v", w, got)
		}
	}

	// The backslash-escape bypass forms are what confirm an app that escapes the
	// quote ('  ->  \') but not the backslash (the ginandjuice.shop catalog case).
	wantBypass := []string{
		"\\';" + alert + "//",
		"\\'-" + alert + "//",
	}
	for _, w := range wantBypass {
		if !containsExact(got, w) {
			t.Errorf("missing backslash-escape bypass payload %q in %v", w, got)
		}
	}

	// Operator chaining must come before the terminator fallback (most-general first).
	if !strings.HasPrefix(got[0], "'^") {
		t.Errorf("expected XOR chaining first, got %q", got[0])
	}

	// Every payload must carry the alert expression verbatim so the body check and
	// the browser dialog can both attribute it.
	for _, p := range got {
		if !strings.Contains(p, alert) {
			t.Errorf("payload %q dropped the alert expression", p)
		}
	}
}

func TestJSStringPayloads_DoubleQuote(t *testing.T) {
	alert := "alert(`c`)"
	got := JSStringPayloads('"', alert)
	// The bare forms open with the quote; the backslash-escape bypass forms open
	// with a backslash. Every payload must begin with one or the other.
	for _, p := range got {
		if !strings.HasPrefix(p, `"`) && !strings.HasPrefix(p, `\"`) {
			t.Errorf(`double-quote payload must open with " or \", got %q`, p)
		}
	}
	if !containsExact(got, `"^`+alert+`^"`) {
		t.Errorf("missing double-quote XOR chaining payload in %v", got)
	}
	if !containsExact(got, `\";`+alert+`//`) {
		t.Errorf("missing double-quote backslash-escape bypass payload in %v", got)
	}
}

// TestJSStringPayloads_ContractBareAndBackslashForms locks the payload set for every
// quote style: there must always be at least one bare-quote breakout AND at least one
// backslash-escape bypass form, each carrying the alert. The backslash forms are what
// confirm apps that escape the quote but not the backslash (ginandjuice.shop /
// dialog1.acme.com); removing them silently would let those XSS go missed again.
func TestJSStringPayloads_ContractBareAndBackslashForms(t *testing.T) {
	const alert = "alert(`vigxc0`)"
	for _, quote := range []byte{'\'', '"', '`'} {
		q := string(quote)
		got := JSStringPayloads(quote, alert)
		var hasBare, hasBackslash bool
		for _, p := range got {
			switch {
			case strings.HasPrefix(p, `\`+q):
				hasBackslash = true
			case strings.HasPrefix(p, q):
				hasBare = true
			}
			if !strings.Contains(p, alert) {
				t.Errorf("quote %q: payload %q dropped the alert expression", quote, p)
			}
		}
		if !hasBare {
			t.Errorf("quote %q: no bare-quote breakout payload in %v", quote, got)
		}
		if !hasBackslash {
			t.Errorf("quote %q: no backslash-escape bypass payload in %v — the ginandjuice/acme fix regressed", quote, got)
		}
	}
}

// jsStringExecutes is a minimal JavaScript tokenizer that reports whether alertExpr
// begins at a TOP-LEVEL position — not inside a '...', "..." or `...` string literal.
// It is the ground truth for "would this rendered script actually run", independent
// of any scanner module: a payload only breaks out when the surviving bytes place
// alert() outside every string.
func jsStringExecutes(js, alertExpr string) bool {
	var q byte // current open string delimiter; 0 = top level
	for i := 0; i < len(js); i++ {
		c := js[i]
		if q == 0 {
			switch c {
			case '\'', '"', '`':
				q = c
			default:
				if strings.HasPrefix(js[i:], alertExpr) {
					return true
				}
			}
			continue
		}
		if c == '\\' {
			i++ // escape: skip the escaped char too
			continue
		}
		if c == q {
			q = 0
		}
	}
	return false
}

// TestJSStringPayloads_SemanticBreakoutMatrix is the crown-jewel regression: it
// renders every generated payload through the escaping a real app applies and checks
// (via jsStringExecutes) whether it ACTUALLY breaks out. This proves, at the source
// shared by all three XSS modules, that:
//
//   - verbatim reflection            -> the bare-quote forms execute;
//   - escape-the-quote-not-backslash -> the backslash bypass forms execute while the
//     bare forms are neutralized (the exact ginandjuice.shop / dialog1.acme.com bug);
//   - escape both quote and backslash -> nothing executes (no false confirmation).
func TestJSStringPayloads_SemanticBreakoutMatrix(t *testing.T) {
	const marker = "vigxsem1"
	alert := "alert(`" + marker + "`)"

	identity := func(s string) string { return s }
	escapeQuoteOnly := func(quote byte) func(string) string {
		q := string(quote)
		return func(s string) string { return strings.ReplaceAll(s, q, `\`+q) }
	}
	escapeBoth := func(quote byte) func(string) string {
		q := string(quote)
		r := strings.NewReplacer(`\`, `\\`, q, `\`+q)
		return func(s string) string { return r.Replace(s) }
	}
	render := func(quote byte, escape func(string) string, payload string) string {
		q := string(quote)
		return "var v = " + q + escape(payload) + q + ";"
	}

	// The state machine models ' and " reliably; backtick/template-literal ${}
	// interpolation is out of its scope, so the semantic pass covers ' and ".
	for _, quote := range []byte{'\'', '"'} {
		payloads := JSStringPayloads(quote, alert)
		countExec := func(escape func(string) string) int {
			n := 0
			for _, p := range payloads {
				if jsStringExecutes(render(quote, escape, p), alert) {
					n++
				}
			}
			return n
		}

		if countExec(identity) == 0 {
			t.Errorf("quote %q: no payload executes on a verbatim-reflecting app", quote)
		}
		if countExec(escapeQuoteOnly(quote)) == 0 {
			t.Errorf("quote %q: no payload executes on an escape-quote-only app — the backslash bypass regressed", quote)
		}
		if n := countExec(escapeBoth(quote)); n != 0 {
			t.Errorf("quote %q: %d payload(s) executed on a fully-escaped app, want 0 (false confirmation)", quote, n)
		}

		// Pin the exact ginandjuice mechanism: the bare terminator is neutralized by
		// quote-escaping, and the backslash terminator is what recovers the breakout.
		bareTerm := string(quote) + ";" + alert + "//"
		bsTerm := `\` + string(quote) + ";" + alert + "//"
		if jsStringExecutes(render(quote, escapeQuoteOnly(quote), bareTerm), alert) {
			t.Errorf("quote %q: bare terminator should be neutralized on an escape-quote app", quote)
		}
		if !jsStringExecutes(render(quote, escapeQuoteOnly(quote), bsTerm), alert) {
			t.Errorf("quote %q: backslash terminator must break out on an escape-quote app", quote)
		}
	}
}

func containsExact(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
