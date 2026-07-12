package sqli_boolean_blind_test

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/active/sqli_boolean_blind"
)

// TestModuleSatisfiesContextual is a compile-time guard: the module must satisfy
// ContextualActiveModule so the executor threads the per-module deadline into
// ScanPerRequestContext (the deadline-aware early return). If any of the three
// Context methods is dropped, this stops compiling.
func TestModuleSatisfiesContextual(t *testing.T) {
	var _ modules.ContextualActiveModule = sqli_boolean_blind.New()
}
