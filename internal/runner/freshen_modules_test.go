package runner

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/active/authz_compare"
	"github.com/vigolium/vigolium/pkg/modules/active/nextjs_chunk_audit"
)

// TestFreshenPerScanModules verifies that per-scan-stateful modules are replaced
// with fresh instances (so concurrent scans can't share their mutable state)
// while non-stateful modules and the input slice are left untouched.
func TestFreshenPerScanModules(t *testing.T) {
	authz := authz_compare.New()
	nextjs := nextjs_chunk_audit.New()

	// A pass-through module: any active module that isn't one of the swapped types.
	var passthrough modules.ActiveModule
	for _, m := range modules.GetActiveModules() {
		switch m.(type) {
		case *authz_compare.Module, *nextjs_chunk_audit.Module:
			// skip the ones that get swapped
		default:
			passthrough = m
		}
		if passthrough != nil {
			break
		}
	}
	if passthrough == nil {
		t.Fatal("no non-stateful active module available for the pass-through check")
	}

	in := []modules.ActiveModule{authz, nextjs, passthrough}
	out := freshenPerScanModules(in)

	if len(out) != len(in) {
		t.Fatalf("length changed: got %d, want %d", len(out), len(in))
	}
	if out[0] == in[0] {
		t.Error("authz_compare should be a fresh instance, not the shared singleton")
	}
	if _, ok := out[0].(*authz_compare.Module); !ok {
		t.Errorf("authz_compare swap produced wrong type %T", out[0])
	}
	if out[1] == in[1] {
		t.Error("nextjs_chunk_audit should be a fresh instance, not the shared singleton")
	}
	if _, ok := out[1].(*nextjs_chunk_audit.Module); !ok {
		t.Errorf("nextjs_chunk_audit swap produced wrong type %T", out[1])
	}
	if out[2] != in[2] {
		t.Error("non-stateful module should pass through unchanged")
	}

	// The input slice (which may carry the registry singletons) must be untouched.
	if in[0] != authz || in[1] != nextjs {
		t.Error("freshenPerScanModules mutated its input slice / the registry singletons")
	}
}
