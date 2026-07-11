package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

// isDiscoveryPhaseArg reports whether the given `vigolium run <phase>` arg
// refers to the discovery or spidering phase (including aliases).
func isDiscoveryPhaseArg(phase string) bool {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "discover", "discovery", "deparos",
		"spidering", "spitolas":
		return true
	}
	return false
}

// isDiscoveryOnlyPhases reports whether every phase in a comma-separated
// --only value refers to discovery or spidering. Used to credit the
// discovery co-authors in the scan banner.
func isDiscoveryOnlyPhases(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	for _, p := range strings.Split(raw, ",") {
		if !isDiscoveryPhaseArg(p) {
			return false
		}
	}
	return true
}

var runCmd = &cobra.Command{
	Use:   "run <phase>",
	Short: "Run a single native scan phase (alias for scan --only <phase>)",
	Long: `Run a single scan phase directly. Equivalent to "vigolium scan --only <phase>".

Valid phases: ingestion, discovery (deparos), external-harvest, spidering (spitolas), known-issue-scan (cve, kis), dynamic-assessment (dast, audit, assessment), extension (ext)`,
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"r"},
	RunE: func(cmd *cobra.Command, args []string) error {
		globalOnly = args[0]
		// The positional arg is the phase name, not a target — pass nil so
		// runScanCmd does not merge it into the scan target list.
		return runScanCmd(cmd, nil)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	flags := runCmd.Flags()
	registerInputSourceFlags(flags)
	registerHTTPClientFlags(flags)
	registerScanModuleFlags(flags)
	registerScanPipelineFlags(flags)
	registerSpecFlags(flags)
	registerNativeScanFlags(flags, true)
}
