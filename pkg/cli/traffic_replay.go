package cli

import (
	"context"
)

// runTrafficReplayShim implements `traffic --replay` as a shortcut for
// `vigolium replay` in bulk mode. There is one replay implementation — the
// pkg/replay engine — and this hands traffic's own record selection to it
// rather than re-sending records itself.
//
// Selection is buildTrafficFilters, the same call the listing path makes, so
// `--replay` re-sends exactly the records the command would otherwise have
// listed — including the -n/--limit cap. Only send behaviour is mapped onto
// replay's flag globals.
//
// Behavioural contract with the standalone command:
//   - traffic's default output is the human comparison table, so --pretty is
//     forced unless -j/--json asked for the machine shape.
//   - traffic --replay never followed redirects; the shortcut keeps that by
//     setting --no-redirects, since following them changes the status a
//     comparison reports.
//
// Flags with no traffic equivalent (-H/--header, --auth-session, --target,
// --session-id, --raw-request, the Burp send/stage targets) are reachable by
// invoking `vigolium replay` directly.
func runTrafficReplayShim(ctx context.Context, fuzzyTerm string) error {
	applyTrafficReplayFlags()

	if err := validateReplayFlags(); err != nil {
		return err
	}

	filters, err := buildTrafficFilters(fuzzyTerm)
	if err != nil {
		return err
	}

	rr, err := newReplayRun()
	if err != nil {
		return err
	}
	return runReplayBulk(ctx, rr, filters)
}

// applyTrafficReplayFlags maps traffic's send-behaviour flags onto replay's
// globals. Record selection is deliberately not mapped — the shim passes
// traffic's own database.QueryFilters straight through, so a filter added to
// `traffic` reaches `--replay` with no second mapping to keep in sync.
func applyTrafficReplayFlags() {
	replayConcurrency = trafficReplayConcurrency
	replayWithBrowser = trafficReplayBrowser
	replayTimeout = globalTimeout
	replayBurpBridgeURL = trafficBurpBridgeURL
	// traffic --replay has never followed redirects; preserve that so the
	// reported status is the one the server answered with directly.
	replayNoRedirects = true
	// Output shape: tables unless the caller asked for JSON.
	replayPretty = !globalJSON
}
