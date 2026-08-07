package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/olium"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// agentSetupHelpLine is the one-line pointer appended to the Long help of the
// agent-family commands, so `vigolium agent` / `vigolium olium --help` always
// name the setup guide even on a successful run.
const agentSetupHelpLine = "Setting up a provider (API key, OAuth, or a local model): " + olium.SetupDocsURL

// agentSetupCommandNames are the command names that root the agent family.
// Matching by name (rather than by pointer) covers every entry point without a
// per-command registration step: the `agent` parent covers query/autopilot/
// swarm/olium/audit/session, and the two top-level aliases — `olium` (alias
// `ol`) and `audit` — are named here because they hang off root, not `agent`.
var agentSetupCommandNames = map[string]bool{
	"agent": true,
	"olium": true,
	"audit": true,
}

// isAgentSetupCommand reports whether cmd belongs to the agent family, walking
// up the parent chain so a subcommand (`agent autopilot`) matches through its
// parent. Cobra resolves aliases to the canonical command before we see it, so
// `ol` arrives as `olium`.
func isAgentSetupCommand(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if agentSetupCommandNames[c.Name()] {
			return true
		}
	}
	return false
}

// printAgentSetupHint writes the setup-guide pointer. It fires on *any* error
// out of an agent command: a first-run agent failure is nearly always a
// missing/mismatched provider credential, and the remaining cases (a usage
// slip) cost one muted line. Suppressed under --silent, which promises no
// decoration on stderr.
func printAgentSetupHint(w io.Writer) {
	if globalSilent {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s Agent setup guide: %s\n",
		terminal.InfoSymbol(),
		terminal.Cyan(olium.SetupDocsURL))
}
