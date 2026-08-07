package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/olium"
)

// TestIsAgentSetupCommand walks the real command tree so a newly registered
// agent subcommand is covered automatically, and a rename of one of the
// top-level aliases (`olium`, `audit`) is caught here rather than by a user
// who silently stops getting the hint.
func TestIsAgentSetupCommand(t *testing.T) {
	find := func(path ...string) *cobra.Command {
		t.Helper()
		cmd, _, err := rootCmd.Find(path)
		if err != nil {
			t.Fatalf("Find(%v): %v", path, err)
		}
		// Find falls back to the closest ancestor it could resolve, so verify
		// we actually landed on the requested leaf.
		if cmd.Name() != path[len(path)-1] {
			t.Fatalf("Find(%v) resolved to %q, not the requested command", path, cmd.Name())
		}
		return cmd
	}

	agentFamily := [][]string{
		{"agent"},
		{"agent", "query"},
		{"agent", "autopilot"},
		{"agent", "swarm"},
		{"agent", "olium"},
		{"agent", "audit"},
		{"olium"}, // top-level alias
		{"audit"}, // top-level alias
	}
	for _, path := range agentFamily {
		if !isAgentSetupCommand(find(path...)) {
			t.Errorf("isAgentSetupCommand(%v) = false, want true", path)
		}
	}

	// `ol` is a cobra alias — Find resolves it to the canonical command, which
	// is exactly what Execute() hands us.
	if cmd, _, err := rootCmd.Find([]string{"ol"}); err != nil || !isAgentSetupCommand(cmd) {
		t.Errorf("the `ol` alias should resolve into the agent family (err=%v)", err)
	}

	nonAgent := [][]string{
		{"scan"},
		{"finding"},
		{"traffic"},
		{"server"},
		{"fuzz"},
		{"replay"},
	}
	for _, path := range nonAgent {
		if isAgentSetupCommand(find(path...)) {
			t.Errorf("isAgentSetupCommand(%v) = true, want false", path)
		}
	}

	// The root command itself (what ExecuteC returns for an unknown command)
	// must not claim the hint, and a nil command must not panic.
	if isAgentSetupCommand(rootCmd) {
		t.Error("isAgentSetupCommand(rootCmd) = true, want false")
	}
	if isAgentSetupCommand(nil) {
		t.Error("isAgentSetupCommand(nil) = true, want false")
	}
}

// TestPrintAgentSetupHint checks the pointer carries the real URL and that
// --silent suppresses it.
func TestPrintAgentSetupHint(t *testing.T) {
	var buf bytes.Buffer
	printAgentSetupHint(&buf)
	if !strings.Contains(buf.String(), olium.SetupDocsURL) {
		t.Errorf("hint missing %q:\n%s", olium.SetupDocsURL, buf.String())
	}

	prev := globalSilent
	globalSilent = true
	defer func() { globalSilent = prev }()

	buf.Reset()
	printAgentSetupHint(&buf)
	if buf.Len() != 0 {
		t.Errorf("--silent should suppress the hint, got:\n%s", buf.String())
	}
}

// TestAgentSetupHelpLineInLongHelp locks the pointer into the help text of the
// two commands a user reaches for first.
func TestAgentSetupHelpLineInLongHelp(t *testing.T) {
	for _, cmd := range []*cobra.Command{agentCmd, agentOliumCmd, oliumCmd} {
		if !strings.Contains(cmd.Long, olium.SetupDocsURL) {
			t.Errorf("%q Long help does not mention the setup guide", cmd.Name())
		}
	}
}
