package aem

import (
	"strings"
	"testing"
)

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestExtensionBypassesCleanFirstAndVariants(t *testing.T) {
	got := ExtensionBypasses("/bin/querybuilder.json?path=/etc")
	if got[0] != "/bin/querybuilder.json?path=/etc" {
		t.Fatalf("clean path must be first, got %q", got[0])
	}
	for _, want := range []string{
		"/bin/querybuilder.json.css?path=/etc",
		"/bin/querybuilder.json;%0aa.css?path=/etc",
		"/bin/querybuilder.json.;%0aa.css?path=/etc",
		"/bin/querybuilder.json/a.css?path=/etc",
	} {
		if !contains(got, want) {
			t.Errorf("missing extension bypass %q in %v", want, got)
		}
	}
}

func TestTraversalBypassesFormsAndQuery(t *testing.T) {
	got := TraversalBypasses("/bin/querybuilder.json?p.hits=full")
	for _, want := range []string{
		"/content/..;/bin/querybuilder.json?p.hits=full",
		"/..;/bin/querybuilder.json?p.hits=full",
		"///bin///querybuilder.json?p.hits=full",
	} {
		if !contains(got, want) {
			t.Errorf("missing traversal bypass %q in %v", want, got)
		}
	}
	for _, g := range got {
		if !strings.Contains(g, "?p.hits=full") {
			t.Errorf("variant dropped query: %q", g)
		}
	}
}

func TestMatrixParamBypassesFormsAndQuery(t *testing.T) {
	got := MatrixParamBypasses("/bin/querybuilder.json?p.hits=full")
	for _, want := range []string{
		"/graphql/execute.json/..%2f../bin/querybuilder.json?p.hits=full",
		"/bin/querybuilder.json;x='x/graphql/execute/json/x'?p.hits=full",
		"/bin/querybuilder.json;x='.ico/x'?p.hits=full",
		"/bin/querybuilder.json;x='.css/x'?p.hits=full",
		"/bin/querybuilder.json;x='.html/x'?p.hits=full",
		"/bin/querybuilder.json;x='.pdf/x'?p.hits=full",
	} {
		if !contains(got, want) {
			t.Errorf("missing matrix-param bypass %q in %v", want, got)
		}
	}
	// The clean path must NOT be present (callers try it first).
	if contains(got, "/bin/querybuilder.json?p.hits=full") {
		t.Errorf("MatrixParamBypasses must not include the clean path")
	}
	for _, g := range got {
		if !strings.Contains(g, "?p.hits=full") {
			t.Errorf("variant dropped query: %q", g)
		}
	}
}

func TestCappedBypasses(t *testing.T) {
	full := AllBypasses("/content.1.json")
	got := CappedBypasses("/content.1.json", 5)
	if len(got) != 5 {
		t.Fatalf("expected 5 variants, got %d", len(got))
	}
	for i := range got {
		if got[i] != full[i] {
			t.Errorf("capped[%d]=%q, want %q", i, got[i], full[i])
		}
	}
	// A cap at or above the full length returns everything.
	if all := CappedBypasses("/content.1.json", len(full)+3); len(all) != len(full) {
		t.Errorf("cap above length should return all %d, got %d", len(full), len(all))
	}
}

func TestBypassAtIndex(t *testing.T) {
	full := AllBypasses("/bin/querybuilder.json?p.limit=1")
	// Index 0 is the clean path and must equal the input verbatim.
	if got := BypassAtIndex("/bin/querybuilder.json?p.limit=1", 0); got != "/bin/querybuilder.json?p.limit=1" {
		t.Errorf("idx 0 should be the clean path, got %q", got)
	}
	// Every valid index matches AllBypasses.
	for i := range full {
		if got := BypassAtIndex("/bin/querybuilder.json?p.limit=1", i); got != full[i] {
			t.Errorf("BypassAtIndex(%d)=%q, want %q", i, got, full[i])
		}
	}
	// Out-of-range indices return "".
	if got := BypassAtIndex("/x", len(full)); got != "" {
		t.Errorf("out-of-range index should return empty, got %q", got)
	}
	if got := BypassAtIndex("/x", -1); got != "" {
		t.Errorf("negative index should return empty, got %q", got)
	}
}

func TestAllBypassesCleanFirstAndUnion(t *testing.T) {
	got := AllBypasses("/content.1.json")
	if got[0] != "/content.1.json" {
		t.Fatalf("clean path must be first, got %q", got[0])
	}
	// One representative from each family must be present.
	for _, want := range []string{
		"/content.1.json.css",                          // extension
		"///content.1.json",                            // traversal (triple-slash)
		"/graphql/execute.json/..%2f../content.1.json", // graphql traversal
		"/content.1.json;x='.css/x'",                   // matrix param
	} {
		if !contains(got, want) {
			t.Errorf("AllBypasses missing %q in %v", want, got)
		}
	}
	// No duplicates (the three builders emit disjoint forms).
	seen := map[string]bool{}
	for _, g := range got {
		if seen[g] {
			t.Errorf("AllBypasses produced duplicate %q", g)
		}
		seen[g] = true
	}
}
