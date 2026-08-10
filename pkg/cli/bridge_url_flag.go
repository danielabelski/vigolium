package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// bridgeURLFlagName is the canonical spelling of the bridge-address flag.
const bridgeURLFlagName = "burp-bridge-url"

// bridgeURLAliases spells --burp-bridge-url as --caido-bridge-url. What the flag
// points at is a loopback HTTP listener speaking the bridge protocol, not
// anything Burp-specific — the Caido plugin exposes the same one — so the two
// names are one flag routed through addFlagAliases rather than two flags sharing
// a variable, which would let whichever spelling parsed last silently overwrite
// the other.
var bridgeURLAliases = map[string]string{"caido-bridge-url": bridgeURLFlagName}

// bridgeURLAliasNote is the help-text suffix naming the alternate spellings,
// derived from bridgeURLAliases through the same renderer flagAliasLabel uses so
// the table stays the only place a spelling is declared. A normalize-func alias
// registers no flag of its own and so never renders a line in --help; this
// suffix is the only place --help can name it.
var bridgeURLAliasNote = " (alias: " +
	strings.Join(flagAliasSpellings(bridgeURLAliases, bridgeURLFlagName), ", ") + ")"

// preflightBridge probes the listener before an explicit send and warns when it
// will refuse out-of-scope targets. Every send path wants the same two things —
// an up-front "bridge unavailable" error rather than one failure per record
// mid-run, and a scope warning naming the vendor that actually answered — so
// they share one implementation rather than three copies that drift apart the
// next time the wording or the vendor lookup changes.
//
// warnInScope lets a caller suppress the warning when its own flags mean no
// request will be sent through the bridge (`finding --push-to-burp` without
// --send-via-burp hands over evidence rather than issuing it).
func preflightBridge(ctx context.Context, client *burpbridge.Client, warnInScope bool) (burpbridge.HealthInfo, error) {
	info, err := client.Health(ctx)
	if err != nil {
		return burpbridge.HealthInfo{}, fmt.Errorf("bridge unavailable: %w", err)
	}
	if info.InScopeOnly && warnInScope {
		fmt.Fprintf(os.Stderr, "%s %s bridge is in-scope-only; out-of-scope targets will be refused (403)\n",
			terminal.WarningSymbol(), info.VendorName())
	}
	return info, nil
}

// registerBridgeURLFlag declares the bridge-address flag on cmd: canonical name,
// -B shorthand, $VIGOLIUM_BURP_BRIDGE_URL default, the alias, and the help-text
// note naming it. usage is the command-specific sentence; the note is appended.
//
// The three obligations are one call on purpose. Split across a StringVarP here
// and an addFlagAliases there, a new command silently gets the flag without the
// alias — it compiles, it runs, and only a user typing the alias finds out.
func registerBridgeURLFlag(cmd *cobra.Command, target *string, usage string) {
	cmd.Flags().StringVarP(target, bridgeURLFlagName, "B",
		burpbridge.URLFromEnvironment(), usage+bridgeURLAliasNote)
	// Composes with the command's other addFlagAliases calls (the maps
	// accumulate), so ordering against timeFilterAliases is irrelevant.
	addFlagAliases(cmd, bridgeURLAliases)
}
