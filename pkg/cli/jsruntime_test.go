package cli

import (
	"os"
	"strings"
	"testing"
)

// jsEntryPoints are the two ad-hoc JavaScript doors that must expose the
// same vigolium.* surface: `vigolium js` and `vigolium extensions eval`.
var jsEntryPoints = []string{"js.go", "extensions_eval.go"}

// TestJSEntryPointsShareOneOptionsBuilder keeps `vigolium js` and
// `vigolium extensions eval` from drifting apart again.
//
// They previously built jsext.APIOptions independently, and eval's copy
// never constructed an HTTP requester. Because jsext.shouldRegisterNS
// gates whole namespaces on the options it is handed, that silently
// dropped vigolium.http and vigolium.mcp from a command whose own help
// promised the full API surface - a missing namespace at runtime, not a
// visible error. A hand-rolled jsext.APIOptions literal in either file
// is how that regression comes back, so assert neither has one.
func TestJSEntryPointsShareOneOptionsBuilder(t *testing.T) {
	for _, name := range jsEntryPoints {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body := string(src)

		if !strings.Contains(body, "buildJSEvalOptions(") {
			t.Errorf("%s does not call buildJSEvalOptions; both JS entry points must share one options builder", name)
		}
		if strings.Contains(body, "jsext.APIOptions{") {
			t.Errorf("%s builds a jsext.APIOptions literal directly; use buildJSEvalOptions so the two JS entry points cannot drift", name)
		}
	}
}

// TestJSEvalOptionsWiresHTTPNamespace asserts the builder actually
// populates HTTPClient, which is the single field that gates
// vigolium.http and vigolium.mcp registration.
func TestJSEvalOptionsWiresHTTPNamespace(t *testing.T) {
	src, err := os.ReadFile("jsruntime.go")
	if err != nil {
		t.Fatalf("read jsruntime.go: %v", err)
	}
	if !strings.Contains(string(src), "opts.HTTPClient = requester") {
		t.Error("buildJSEvalOptions no longer assigns opts.HTTPClient; vigolium.http and vigolium.mcp would go unregistered")
	}
}

// TestJSEvalBoundsExecution locks the timeout on `extensions eval`. It
// used to call jsext.Eval directly with no deadline, so a stray
// `while(true){}` in a pasted snippet hung the process indefinitely.
func TestJSEvalBoundsExecution(t *testing.T) {
	src, err := os.ReadFile("extensions_eval.go")
	if err != nil {
		t.Fatalf("read extensions_eval.go: %v", err)
	}
	body := string(src)
	if !strings.Contains(body, "evalWithTimeout(") {
		t.Error("extensions eval must run through evalWithTimeout so a runaway script cannot hang the process")
	}
	if !strings.Contains(body, `"timeout"`) {
		t.Error("extensions eval must register a --timeout flag")
	}
}
