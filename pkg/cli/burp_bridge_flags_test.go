package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestBurpBridgeURLFlagsAreAvailable(t *testing.T) {
	if serverCmd.Flags().Lookup("burp-bridge-url") == nil {
		t.Fatal("vigolium server is missing --burp-bridge-url")
	}
	if trafficCmd.Flags().Lookup("burp-bridge-url") == nil {
		t.Fatal("vigolium traffic is missing --burp-bridge-url")
	}
	if importCmd.Flags().Lookup("burp-bridge-url") == nil {
		t.Fatal("vigolium import is missing --burp-bridge-url")
	}
	if trafficCmd.Flags().Lookup("save-to-vigolium-db") == nil {
		t.Fatal("vigolium traffic is missing --save-to-vigolium-db")
	}
	if trafficCmd.Flags().Lookup("save-to-burp") == nil {
		t.Fatal("vigolium traffic is missing --save-to-burp")
	}
	if replayCmd.Flags().Lookup("burp-bridge-url") == nil {
		t.Fatal("vigolium replay is missing --burp-bridge-url")
	}
	if replayCmd.Flags().Lookup("save-to-burp") == nil {
		t.Fatal("vigolium replay is missing --save-to-burp")
	}
}

// TestBurpSendFlagsAreAvailable guards the new Burp-engine send/push flags on
// replay, fuzz, and finding so a rename or dropped registration is caught.
func TestBurpSendFlagsAreAvailable(t *testing.T) {
	for _, flag := range []string{"send-via-burp", "http-mode", "send-timeout", "to-repeater", "repeater-tab", "to-organizer", "notes", "highlight"} {
		if replayCmd.Flags().Lookup(flag) == nil {
			t.Fatalf("vigolium replay is missing --%s", flag)
		}
	}
	for _, flag := range []string{"send-via-burp", "burp-bridge-url", "http-mode", "send-timeout", "matches-to-organizer"} {
		if fuzzCmd.Flags().Lookup(flag) == nil {
			t.Fatalf("vigolium fuzz is missing --%s", flag)
		}
	}
	for _, flag := range []string{"push-to-burp", "to-repeater", "send-via-burp", "http-mode", "burp-bridge-url"} {
		if findingCmd.Flags().Lookup(flag) == nil {
			t.Fatalf("vigolium finding is missing --%s", flag)
		}
	}
}

// bridgeURLCommands discovers every command carrying --burp-bridge-url by
// walking the real command tree, rather than restating a list. A hand-kept list
// only guards the sites already on it — the whole failure mode here is the 8th
// command being added and forgotten, which a list cannot catch by construction.
func bridgeURLCommands(t *testing.T) map[string]*cobra.Command {
	t.Helper()
	found := map[string]*cobra.Command{}
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		// LocalFlags, not Flags: an inherited persistent flag would otherwise
		// report every descendant as a registration site.
		if cmd.LocalFlags().Lookup(bridgeURLFlagName) != nil {
			found[cmd.CommandPath()] = cmd
		}
		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
	if len(found) == 0 {
		t.Fatal("no command registers --" + bridgeURLFlagName + "; the walk is broken")
	}
	return found
}

// TestCaidoBridgeURLAlias guards that --caido-bridge-url resolves to the same
// flag as --burp-bridge-url everywhere the latter is registered. The alias is a
// normalize func, not a second flag, so a Lookup/Set of the alias spelling must
// land on the canonical flag's value — two flags sharing one variable would let
// whichever spelling parsed last silently win.
func TestCaidoBridgeURLAlias(t *testing.T) {
	const want = "http://127.0.0.1:9009"
	for name, cmd := range bridgeURLCommands(t) {
		canonical := cmd.Flags().Lookup(bridgeURLFlagName)
		if canonical == nil {
			t.Fatalf("vigolium %s is missing --burp-bridge-url", name)
		}
		alias := cmd.Flags().Lookup("caido-bridge-url")
		if alias == nil {
			t.Fatalf("vigolium %s does not accept --caido-bridge-url", name)
		}
		if alias != canonical {
			t.Fatalf("vigolium %s: --caido-bridge-url resolves to a different flag than --burp-bridge-url", name)
		}

		previous := canonical.Value.String()
		if err := cmd.Flags().Set("caido-bridge-url", want); err != nil {
			t.Fatalf("vigolium %s: setting --caido-bridge-url: %v", name, err)
		}
		if got := canonical.Value.String(); got != want {
			t.Fatalf("vigolium %s: --caido-bridge-url set %q, --burp-bridge-url reads %q", name, want, got)
		}
		if err := cmd.Flags().Set(bridgeURLFlagName, previous); err != nil {
			t.Fatalf("vigolium %s: restoring --burp-bridge-url: %v", name, err)
		}
		canonical.Changed = false
	}
}

// TestBridgeURLUsageNamesAlias guards that the help text names the alias. A
// normalize-func alias renders no line of its own in --help, so this suffix is
// the only place a Caido user can discover the spelling.
func TestBridgeURLUsageNamesAlias(t *testing.T) {
	for name, cmd := range bridgeURLCommands(t) {
		usage := cmd.Flags().Lookup(bridgeURLFlagName).Usage
		if !strings.Contains(usage, "--caido-bridge-url") {
			t.Errorf("vigolium %s: --burp-bridge-url usage does not name the alias: %q", name, usage)
		}
		if !strings.Contains(usage, "Caido") {
			t.Errorf("vigolium %s: --burp-bridge-url usage does not mention Caido: %q", name, usage)
		}
	}
}
