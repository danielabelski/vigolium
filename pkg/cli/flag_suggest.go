package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// flagErrorFunc augments cobra's flag-parse errors with a "did you mean" hint.
// Cobra suggests near-miss *subcommands* out of the box but says nothing for a
// mistyped *flag*, so `--module` (instead of `--modules`) dead-ends at a bare
// "unknown flag: --module". This closes that gap by pointing at the closest
// registered long flag on the command that actually failed to parse. It is
// installed once on rootCmd; cobra's FlagErrorFunc() walks up to the parent, so
// every subcommand inherits it.
func flagErrorFunc(cmd *cobra.Command, err error) error {
	var notExist *pflag.NotExistError
	if !errors.As(err, &notExist) {
		return err
	}
	// Only long-flag typos ("--module") get a suggestion. An unknown shorthand
	// carries a shortname group (GetSpecifiedShortnames) and rarely has a
	// meaningful near-match, so leave those untouched.
	typed := notExist.GetSpecifiedName()
	if notExist.GetSpecifiedShortnames() != "" || len(typed) < 2 {
		return err
	}
	best := closestFlagName(cmd, typed)
	if best == "" {
		return err
	}
	return fmt.Errorf("%w\n\n  %s Did you mean %s? (run '%s --help' for all flags)",
		err, terminal.InfoSymbol(), terminal.BoldCyan("--"+best), cmd.CommandPath())
}

// closestFlagName returns the registered long flag on cmd nearest to typed by
// Levenshtein distance, or "" when nothing is close enough to be a confident
// suggestion. The accept threshold scales with the typed length (min 2) so a
// short flag doesn't over-suggest. cmd.Flags() is the fully-merged set
// (local + inherited persistent) by the time flag parsing fails.
func closestFlagName(cmd *cobra.Command, typed string) string {
	bestName := ""
	bestDist := -1
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		d := levenshtein(typed, f.Name)
		if bestDist == -1 || d < bestDist {
			bestName, bestDist = f.Name, d
		}
	})
	if bestDist == -1 {
		return ""
	}
	limit := len(typed) / 3
	if limit < 2 {
		limit = 2
	}
	if bestDist <= limit {
		return bestName
	}
	return ""
}

// levenshtein is the classic edit distance between a and b, computed with a
// two-row rolling buffer.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
