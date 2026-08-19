package cli

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/runner"
)

// TestAmbiguousRunPhaseRejectsAudit locks the guard that keeps
// `vigolium run audit` from silently starting a full native module scan
// when the operator meant `vigolium agent audit` (the AI source-code
// audit). "audit" is the only phase alias that collides with a
// top-level command name.
func TestAmbiguousRunPhaseRejectsAudit(t *testing.T) {
	for _, in := range []string{"audit", "AUDIT", "Audit", "  audit  "} {
		err := ambiguousRunPhase(in)
		if err == nil {
			t.Fatalf("ambiguousRunPhase(%q) = nil, want an error", in)
		}
		// The message has to name both destinations, otherwise it tells
		// the operator they are wrong without telling them what to type.
		for _, want := range []string{"dynamic-assessment", "vigolium agent audit"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("ambiguousRunPhase(%q) error %q does not mention %q", in, err, want)
			}
		}
	}
}

// TestAmbiguousRunPhaseAllowsEveryOtherPhase guards against the check
// widening into a general phase validator. Anything that is not the one
// colliding spelling must fall through to parseOnlyPhases, which owns
// real phase validation and its own error message.
func TestAmbiguousRunPhaseAllowsEveryOtherPhase(t *testing.T) {
	for _, in := range []string{
		"ingestion", "discovery", "deparos", "discover", "external-harvest",
		"spidering", "spitolas", "known-issue-scan", "cve", "kis", "known-issues",
		"dynamic-assessment", "dast", "assessment", "extension", "ext",
		"not-a-phase-at-all",
	} {
		if err := ambiguousRunPhase(in); err != nil {
			t.Errorf("ambiguousRunPhase(%q) = %v, want nil", in, err)
		}
	}
}

// TestAuditRemainsAPhaseAliasElsewhere is the other half of the
// contract: the guard is scoped to the positional `run <phase>` form and
// must not have removed the alias itself. `--only audit` and
// `--skip audit` are unambiguous (those flags only ever take phases) and
// stay valid, so dropping the alias would be a needless break.
func TestAuditRemainsAPhaseAliasElsewhere(t *testing.T) {
	if got := runner.NormalizeNativePhase("audit"); got != "dynamic-assessment" {
		t.Errorf("NormalizeNativePhase(\"audit\") = %q, want \"dynamic-assessment\"", got)
	}
}
