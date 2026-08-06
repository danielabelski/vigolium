package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// dbPathEnvVar supplies a default for the --db flag, so a shell can be pinned to
// one database for a whole session (`export VIGOLIUM_DB_PATH=~/scans/acme.sqlite`)
// instead of repeating --db on every command. An explicit --db always wins.
//
// The value goes through config.ExpandPath, so `~` and nested env references
// resolve the same way the config file's database.sqlite.path does.
const dbPathEnvVar = "VIGOLIUM_DB_PATH"

// dbPathEnvAutoStateless records that dbPathEnvVar named a usable database, so
// reads should treat it as a standalone source with project scoping off. It is
// consumed by statelessReadRequested — the one predicate every read path already
// consults — rather than by a list of command names here.
var dbPathEnvAutoStateless bool

// statelessWriteCommands are the commands whose -S/--stateless means "work in a
// throwaway temporary database and discard it", the opposite of pinning a shell
// to a session database. `scan`/`scan-url`/`scan-request`/`run` reject --db
// outright alongside it (runScan, runRunnerScan), and `audit` repoints the
// database at a scratch file mid-run — so for these, an explicit -S makes the
// env var a no-op rather than a --db the user never typed.
//
// Read commands need no such list: they express the same intent by asking
// statelessReadRequested, and both `vigolium audit` and `vigolium agent audit`
// land here on leaf name alone.
var statelessWriteCommands = map[string]bool{
	"scan":         true,
	"scan-url":     true,
	"scan-request": true,
	"run":          true,
	"audit":        true,
}

// statelessWriteRequested reports whether the user explicitly asked cmd for the
// throwaway-database flavor of -S. It reads the flag rather than globalStateless
// because that variable is only one of the bindings behind the name: `audit -S`
// sets auditStateless and `ingest -S` is --scan-on-receive entirely.
func statelessWriteRequested(cmd *cobra.Command) bool {
	if !statelessWriteCommands[cmd.Name()] {
		return false
	}
	f := cmd.Flags().Lookup("stateless")
	return f != nil && f.Changed
}

// applyDBPathEnv resolves dbPathEnvVar into the --db global (and, for reads, the
// stateless-source flag) and prints a one-line notice describing what it did. It
// is a no-op when the var is unset, and never overrides an explicit flag.
//
// The stateless half is deliberately gated on the file already existing: a
// stateless read stats its source and fails when it is missing, so a session
// whose database has not been written yet would otherwise error on the first
// `vigolium finding` instead of printing an empty table.
func applyDBPathEnv(cmd *cobra.Command) {
	raw := strings.TrimSpace(os.Getenv(dbPathEnvVar))
	if raw == "" {
		return
	}

	// An explicit --db wins. Say so when the two disagree — silently preferring
	// one path over another is exactly the kind of thing that gets debugged for
	// ten minutes.
	if explicit := strings.TrimSpace(globalDB); explicit != "" {
		if explicit != raw && config.ExpandPath(explicit) != config.ExpandPath(raw) {
			dbPathEnvNotice(fmt.Sprintf("--db overrides %s (using %s)",
				terminal.BoldCyan(dbPathEnvVar), terminal.BoldYellow(terminal.ShortenHome(explicit))))
		}
		return
	}

	if statelessWriteRequested(cmd) {
		dbPathEnvNotice(fmt.Sprintf("%s: ignoring %s (results go to a temporary database)",
			terminal.BoldCyan("--stateless"), terminal.BoldCyan(dbPathEnvVar)))
		return
	}

	path := config.ExpandPath(raw)
	globalDB = path

	notice := fmt.Sprintf("%s → %s",
		terminal.BoldCyan(dbPathEnvVar), terminal.BoldYellow(terminal.ShortenHome(path)))
	if !statelessReadRequested() && statelessSourceUsable(path) {
		dbPathEnvAutoStateless = true
		notice += terminal.Gray(" (reads: project scoping off)")
	}
	dbPathEnvNotice(notice)
}

// dbPathEnvNotice prints one informational line to stderr, staying quiet in the
// output modes that promise a clean stream (--silent, -j/--json, CI).
func dbPathEnvNotice(msg string) {
	if globalSilent || globalJSON || globalCIOutput {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), msg)
}
