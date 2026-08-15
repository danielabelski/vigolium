package dom_xss_detect

import (
	"fmt"
	"regexp"
	"testing"
)

// statementUsesTainted used to compile `\b` + QuoteMeta(name) + `\b` per tainted
// name per call. These tests pin the replacement to that exact behaviour —
// including its quirks — so the change stays a performance change.

// referenceUsesTainted is the original implementation, kept here as the oracle.
func referenceUsesTainted(statement string, tainted map[string]struct{}) bool {
	for name := range tainted {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
		if re.MatchString(statement) {
			return true
		}
	}
	return false
}

func TestContainsWordBoundedMatchesRegex(t *testing.T) {
	names := []string{
		"x", "el", "data", "userInput", "_private", "a1", "value2",
		// '$' is not an ASCII word character, so `\b` behaves unintuitively at a
		// name's '$' edges. These are the cases the fast path must not "fix".
		"$", "$el", "$$", "el$", "$data$", "a$b",
		// Regex metacharacters, previously handled by QuoteMeta.
		"a.b", "a[0]", "a(b)", "a|b", "a+b", "a*b",
	}

	statements := []string{
		"",
		"x",
		"$el",
		"el.innerHTML = x;",
		"document.write(data)",
		"var userInput = location.hash;",
		"foo.userInput = 1",
		"userInputExtra = 2",
		"prefix_x_suffix",
		"a$b = 1",
		"$($el).html(data)",
		"window.$ = jQuery",
		"obj.$el.innerHTML = value2",
		"_private=1",
		"my_private = 1",
		"a.b.c",
		"a[0] = 1",
		"a(b)",
		"a|b",
		"a+b",
		"a*b",
		"el$ = 1",
		"$data$ = location.search",
		"xx",
		"x x",
		"(x)",
		"$$",
	}

	for _, name := range names {
		tainted := map[string]struct{}{name: {}}
		for _, stmt := range statements {
			want := referenceUsesTainted(stmt, tainted)
			got := statementUsesTainted(stmt, tainted)
			if got != want {
				t.Errorf("statementUsesTainted(%q, {%q}) = %v, regex oracle = %v",
					stmt, name, got, want)
			}
		}
	}
}

// The multi-name path must agree with the oracle too: a match on any tainted
// name is a match, and the scan must keep searching past a bounded-out hit.
func TestStatementUsesTaintedMultipleNames(t *testing.T) {
	tainted := map[string]struct{}{
		"userInput": {},
		"$el":       {},
		"tmp":       {},
	}

	cases := []struct {
		statement string
		want      bool
	}{
		{"el.innerHTML = userInput;", true},
		{"el.innerHTML = tmp;", true},
		// "userInputExtra" contains "userInput" but not as a whole word, and
		// "tmpX" likewise — neither should match.
		{"el.innerHTML = userInputExtra + tmpX;", false},
		{"el.innerHTML = safe;", false},
		// Occurrence rejected on boundary at first hit, accepted later.
		{"userInputExtra = 1; sink(userInput);", true},
	}

	for _, tc := range cases {
		if got := statementUsesTainted(tc.statement, tainted); got != tc.want {
			t.Errorf("statementUsesTainted(%q) = %v, want %v", tc.statement, got, tc.want)
		}
		if want := referenceUsesTainted(tc.statement, tainted); want != tc.want {
			t.Errorf("oracle disagrees with the expectation for %q: %v", tc.statement, want)
		}
	}
}

func BenchmarkStatementUsesTainted(b *testing.B) {
	const stmt = `document.getElementById("out").innerHTML = someOtherThing + windowLocationHash;`

	for _, n := range []int{5, 20} {
		tainted := make(map[string]struct{}, n)
		for i := 0; i < n; i++ {
			tainted[fmt.Sprintf("taintedVar%d", i)] = struct{}{}
		}

		b.Run(fmt.Sprintf("regex/%dvars", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				referenceUsesTainted(stmt, tainted)
			}
		})
		b.Run(fmt.Sprintf("scan/%dvars", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				statementUsesTainted(stmt, tainted)
			}
		})
	}
}
