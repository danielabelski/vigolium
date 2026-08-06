package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/pkg/input/formats/burpscope"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// burpScopeNoticed tracks which scope files have already had their expansion
// summary printed. readTargetFileLines runs more than once per invocation (flag
// validation, then the fan-out or stateless path), and repeating the "N
// wildcard rules skipped" banner each time reads as though something went wrong
// twice.
var (
	burpScopeNoticedMu sync.Mutex
	burpScopeNoticed   = map[string]struct{}{}
)

// colorizeBurpScopeStats renders the expansion tally with each count picked out
// in the same orange the scan banner uses for its target numbers, so the counts
// read at a glance against the plain labels.
func colorizeBurpScopeStats(stats []burpscope.Stat) string {
	parts := make([]string, 0, len(stats))
	for _, s := range stats {
		parts = append(parts, terminal.Orange(strconv.Itoa(s.Count))+" "+s.Label)
	}
	return strings.Join(parts, " · ")
}

// expandBurpScopeTargets turns a Burp Suite scope export into the seed URLs its
// enabled include rules describe, reporting what was skipped.
func expandBurpScopeTargets(path string) ([]string, error) {
	res, err := burpscope.TargetURLs(path)
	if err != nil {
		return nil, err
	}

	zap.L().Info("expanded burp scope file",
		zap.String("file", path),
		zap.Int("targets", len(res.URLs)),
		zap.Strings("wildcard_hosts", res.WildcardHosts),
		zap.Int("excluded", res.Excluded),
		zap.Int("collapsed_http", res.CollapsedHTTP))

	burpScopeNoticedMu.Lock()
	_, seen := burpScopeNoticed[path]
	burpScopeNoticed[path] = struct{}{}
	burpScopeNoticedMu.Unlock()

	if !seen && !globalSilent {
		fmt.Fprintf(os.Stderr, "%s Detected Burp scope as target input: %s\n",
			terminal.InfoSymbol(), terminal.Cyan(filepath.Base(path)))
		fmt.Fprintf(os.Stderr, "  %s\n", colorizeBurpScopeStats(res.Stats()))
		if len(res.WildcardHosts) > 0 {
			// A wildcard rule names a set of hosts, not a host — there is no
			// request to send at "*.example.com". Say so plainly rather than
			// inventing an apex the scope never listed.
			fmt.Fprintf(os.Stderr, "  %s wildcard entries have no concrete host — seed one with %s (%s)\n",
				terminal.TipPrefix(), terminal.HiCyan("-t"), res.WildcardSample(2))
		}
	}

	if len(res.URLs) == 0 {
		return nil, fmt.Errorf("burp scope file %q yielded no scannable targets (every include rule is a wildcard, disabled, or excluded)", path)
	}
	return res.URLs, nil
}
