package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuditFlagDefaults locks the operator-facing flag contract for the audit
// command: --keep-raw is on by default, --clean-raw / --stateless default off,
// and -S/-o carry their short forms.
func TestAuditFlagDefaults(t *testing.T) {
	f := agentAuditCmd.Flags()

	keepRaw := f.Lookup("keep-raw")
	require.NotNil(t, keepRaw, "keep-raw flag must exist")
	assert.Equal(t, "true", keepRaw.DefValue, "keep-raw must default ON")

	cleanRaw := f.Lookup("clean-raw")
	require.NotNil(t, cleanRaw, "clean-raw flag must exist")
	assert.Equal(t, "false", cleanRaw.DefValue)

	stateless := f.Lookup("stateless")
	require.NotNil(t, stateless, "stateless flag must exist")
	assert.Equal(t, "false", stateless.DefValue)
	assert.Equal(t, "S", stateless.Shorthand, "stateless must keep the -S short form")

	output := f.Lookup("output")
	require.NotNil(t, output, "output flag must exist")
	assert.Equal(t, "o", output.Shorthand, "output must keep the -o short form")

	outputDir := f.Lookup("output-dir")
	require.NotNil(t, outputDir, "output-dir flag must exist")
	assert.Equal(t, "", outputDir.DefValue, "output-dir must default empty (off)")
	assert.Equal(t, "", outputDir.Shorthand, "output-dir has no short form (-o is taken)")
}

// TestResolveAuditReportDest walks the report-destination / bundle-dir matrix
// for --stateless runs: no bundle passes -o through; a bundle defaults the
// report name, nests a relative -o, and lets an absolute path or gs:// URL win.
func TestResolveAuditReportDest(t *testing.T) {
	// No --output-dir: -o passes straight through, no bundle dir.
	dest, bundle, err := resolveAuditReportDest("", "reports/r.html")
	require.NoError(t, err)
	assert.Equal(t, "reports/r.html", dest)
	assert.Equal(t, "", bundle, "no bundle dir without --output-dir")

	// No --output-dir and no -o: emit falls back to its own default (empty).
	dest, bundle, err = resolveAuditReportDest("", "")
	require.NoError(t, err)
	assert.Equal(t, "", dest)
	assert.Equal(t, "", bundle)

	// Bundle + empty -o: report defaults to <bundle>/vigolium-audit-report.html.
	dest, bundle, err = resolveAuditReportDest("out", "")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("out", auditBundleReportName), dest)
	assert.Equal(t, "out", bundle)

	// Bundle + relative -o: nested under the bundle.
	dest, bundle, err = resolveAuditReportDest("out", "custom.html")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("out", "custom.html"), dest)
	assert.Equal(t, "out", bundle)

	// Bundle + absolute -o: the explicit path wins verbatim (escapes bundle).
	abs := filepath.Join(t.TempDir(), "abs.html")
	dest, bundle, err = resolveAuditReportDest("out", abs)
	require.NoError(t, err)
	assert.Equal(t, abs, dest)
	assert.Equal(t, "out", bundle, "bundle dir still receives the raw copy")

	// Bundle + gs:// -o: uploaded verbatim, bundle still collects raw results.
	dest, bundle, err = resolveAuditReportDest("out", "gs://proj/reports/r.html")
	require.NoError(t, err)
	assert.Equal(t, "gs://proj/reports/r.html", dest)
	assert.Equal(t, "out", bundle)
}

// TestResolveAuditReportDest_TimestampShared confirms a {ts} placeholder in
// --output-dir is expanded once, so the report path and the bundle dir (which
// receives the raw copy) resolve to the SAME directory.
func TestResolveAuditReportDest_TimestampShared(t *testing.T) {
	dest, bundle, err := resolveAuditReportDest("bundle-{ts}", "")
	require.NoError(t, err)
	assert.NotContains(t, bundle, "{ts}", "{ts} must be expanded in the bundle dir")
	assert.NotContains(t, dest, "{ts}", "{ts} must be expanded in the report path")
	assert.Equal(t, filepath.Join(bundle, auditBundleReportName), dest,
		"report must sit inside the resolved bundle dir")
}

// TestBundleAuditRawResults_SingleDriver copies one driver's synced
// vigolium-results/ tree into <bundle>/vigolium-results (flat, no namespacing).
func TestBundleAuditRawResults_SingleDriver(t *testing.T) {
	sess := t.TempDir()
	seedRawResults(t, sess, "findings/f1.json", `{"id":1}`)
	plans := []*driverPlan{{name: "audit", sessionDir: sess}}

	bundle := filepath.Join(t.TempDir(), "bundle")
	n, err := bundleAuditRawResults(bundle, plans)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	got, readErr := os.ReadFile(filepath.Join(bundle, "vigolium-results", "findings", "f1.json"))
	require.NoError(t, readErr, "raw results must be copied flat under the bundle")
	assert.Equal(t, `{"id":1}`, string(got))
}

// TestBundleAuditRawResults_SkipsFailedAndMissing ignores drivers that errored
// or produced no vigolium-results/ folder.
func TestBundleAuditRawResults_SkipsFailedAndMissing(t *testing.T) {
	okSess := t.TempDir()
	seedRawResults(t, okSess, "report.md", "ok")
	failSess := t.TempDir()
	seedRawResults(t, failSess, "report.md", "partial")
	emptySess := t.TempDir() // no vigolium-results/ at all

	plans := []*driverPlan{
		{name: "audit", sessionDir: okSess},
		{name: "piolium", sessionDir: failSess, runErr: errDriverFailed},
		{name: "extra", sessionDir: emptySess},
	}

	bundle := filepath.Join(t.TempDir(), "bundle")
	n, err := bundleAuditRawResults(bundle, plans)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only the one successful driver with output is copied")

	// The single survivor lands flat (namespacing only kicks in for >1 copy).
	_, statErr := os.Stat(filepath.Join(bundle, "vigolium-results", "report.md"))
	require.NoError(t, statErr)
}

// TestBundleAuditRawResults_MultiDriverNamespaced namespaces each driver's tree
// under <bundle>/<driver>/vigolium-results when more than one produced output.
func TestBundleAuditRawResults_MultiDriverNamespaced(t *testing.T) {
	auditSess := t.TempDir()
	seedRawResults(t, auditSess, "a.md", "A")
	pioliumSess := t.TempDir()
	seedRawResults(t, pioliumSess, "p.md", "P")

	plans := []*driverPlan{
		{name: "audit", sessionDir: auditSess},
		{name: "piolium", sessionDir: pioliumSess},
	}

	bundle := filepath.Join(t.TempDir(), "bundle")
	n, err := bundleAuditRawResults(bundle, plans)
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	_, aErr := os.Stat(filepath.Join(bundle, "audit", "vigolium-results", "a.md"))
	require.NoError(t, aErr, "audit tree must be namespaced")
	_, pErr := os.Stat(filepath.Join(bundle, "piolium", "vigolium-results", "p.md"))
	require.NoError(t, pErr, "piolium tree must be namespaced")
}

// TestBundleAuditRawResults_Empty returns (0, nil) with no plans and creates
// nothing.
func TestBundleAuditRawResults_Empty(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "bundle")
	n, err := bundleAuditRawResults(bundle, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	_, statErr := os.Stat(bundle)
	assert.True(t, os.IsNotExist(statErr), "no bundle dir created when there's nothing to copy")
}

// errDriverFailed is a sentinel non-nil error for driverPlan.runErr in tests.
var errDriverFailed = errors.New("driver failed")

// seedRawResults writes one file at <sessionDir>/vigolium-results/<rel> with
// the given content, creating parent dirs — mimicking the audit harness's
// synced session copy.
func seedRawResults(t *testing.T, sessionDir, rel, content string) {
	t.Helper()
	dest := filepath.Join(sessionDir, "vigolium-results", rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(dest), 0o755))
	require.NoError(t, os.WriteFile(dest, []byte(content), 0o644))
}

// TestAuditAliasSharesFlags verifies the top-level `vigolium audit` alias is
// wired to the same RunE and exposes the same flag set as `vigolium agent
// audit` (both go through registerAuditFlags).
func TestAuditAliasSharesFlags(t *testing.T) {
	require.NotNil(t, auditCmd.RunE, "auditCmd must have a RunE")
	assert.Equal(t, "audit", auditCmd.Name())

	// The alias must surface the audit-specific flags so users get identical
	// behavior regardless of entry point.
	for _, name := range []string{"keep-raw", "clean-raw", "stateless", "output", "driver", "mode"} {
		assert.NotNilf(t, auditCmd.Flags().Lookup(name),
			"alias `vigolium audit` is missing --%s", name)
	}

	// Both entry points share the same Examples block.
	assert.NotEmpty(t, auditCmd.Example, "alias should carry usage examples")
	assert.Equal(t, agentAuditCmd.Example, auditCmd.Example,
		"alias and subcommand must show identical examples")
}

// TestKeepSourceResults walks the keep-raw / clean-raw truth table that decides
// whether <source>/vigolium-results/ survives in the source tree.
func TestKeepSourceResults(t *testing.T) {
	origKeep, origClean := auditKeepRaw, auditCleanRaw
	t.Cleanup(func() { auditKeepRaw, auditCleanRaw = origKeep, origClean })

	cases := []struct {
		keepRaw  bool
		cleanRaw bool
		want     bool
	}{
		{true, false, true},   // default: keep the source copy
		{true, true, false},   // --clean-raw wins
		{false, false, false}, // --keep-raw=false: clean (legacy behavior)
		{false, true, false},
	}
	for _, c := range cases {
		auditKeepRaw, auditCleanRaw = c.keepRaw, c.cleanRaw
		if got := keepSourceResults(); got != c.want {
			t.Errorf("keepSourceResults(keepRaw=%v, cleanRaw=%v) = %v, want %v",
				c.keepRaw, c.cleanRaw, got, c.want)
		}
	}
}

// TestEmitAuditStatelessReport_DefaultPath renders the report with no -o
// override and confirms it lands at the documented default location, contains
// the seeded finding, and reports the right count.
func TestEmitAuditStatelessReport_DefaultPath(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj-audit", "alpha")
	seedFindingAndRecord(t, db, "proj-audit", "beta")

	// Run in a temp CWD so the default relative path is created in isolation.
	cwd, err := os.Getwd()
	require.NoError(t, err)
	tmp := t.TempDir()
	require.NoError(t, os.Chdir(tmp))
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	err = emitAuditStatelessReport(context.Background(), db, "proj-audit", "", "/some/source", timeAnchor())
	require.NoError(t, err)

	reportPath := filepath.Join(tmp, defaultAuditStatelessReport)
	data, readErr := os.ReadFile(reportPath)
	require.NoError(t, readErr, "default report must be written to %s", defaultAuditStatelessReport)
	assert.Contains(t, string(data), "alpha.example")
	assert.Contains(t, string(data), "beta.example")
}

// TestEmitAuditStatelessReport_OutputOverride confirms -o/--output redirects the
// report and that only the scoped project's findings are included.
func TestEmitAuditStatelessReport_OutputOverride(t *testing.T) {
	db := newExportTestDB(t)
	seedFindingAndRecord(t, db, "proj-keep", "kept")
	seedFindingAndRecord(t, db, "proj-other", "dropped")

	out := filepath.Join(t.TempDir(), "nested", "report.html")
	err := emitAuditStatelessReport(context.Background(), db, "proj-keep", out, "/src", timeAnchor())
	require.NoError(t, err)

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr, "the -o override path (with a new parent dir) must be created")
	assert.Contains(t, string(data), "kept.example")
	assert.NotContains(t, string(data), "dropped.example",
		"the report must be scoped to the run's project")
}

// TestEmitAuditStatelessReport_EmptyDB still produces a valid (empty) report
// rather than erroring, so a clean audit with zero findings yields a file.
func TestEmitAuditStatelessReport_EmptyDB(t *testing.T) {
	db := newExportTestDB(t)
	out := filepath.Join(t.TempDir(), "empty.html")
	err := emitAuditStatelessReport(context.Background(), db, "proj-empty", out, "", timeAnchor())
	require.NoError(t, err)
	_, statErr := os.Stat(out)
	require.NoError(t, statErr)
}

// timeAnchor returns a start time for the report's duration field. Tests don't
// assert on the rendered duration, only that report generation succeeds.
func timeAnchor() time.Time { return time.Now() }

// saveAuditGlobals snapshots the package-level audit flag vars and restores
// them on cleanup so the validation tests don't leak state into siblings.
func saveAuditGlobals(t *testing.T) {
	t.Helper()
	d, a, i, k, c, s, lm := auditDriver, auditAgent, auditInteractive,
		auditKeepRaw, auditCleanRaw, auditStateless, auditListModes
	t.Cleanup(func() {
		auditDriver, auditAgent, auditInteractive = d, a, i
		auditKeepRaw, auditCleanRaw, auditStateless, auditListModes = k, c, s, lm
	})
}

// TestAuditStatelessRejectsInteractive: -S and --interactive both want the
// terminal/DB in incompatible ways, so the combination must fail fast before
// any work (no temp DB, no clone).
func TestAuditStatelessRejectsInteractive(t *testing.T) {
	saveAuditGlobals(t)
	auditListModes = false
	auditStateless = true
	auditInteractive = true

	err := runAgentAudit(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stateless")
	assert.Contains(t, err.Error(), "interactive")
}

// TestAuditKeepRawCleanRawMutuallyExclusive: explicitly passing both --keep-raw
// and --clean-raw is contradictory and must error (the default-on keep-raw must
// NOT trip this — only an explicit set does).
func TestAuditKeepRawCleanRawMutuallyExclusive(t *testing.T) {
	saveAuditGlobals(t)
	auditListModes = false
	auditStateless = false
	auditInteractive = false

	c := &cobra.Command{Use: "audit", RunE: runAgentAudit}
	registerAuditFlags(c)
	require.NoError(t, c.Flags().Set("driver", "audit"))
	require.NoError(t, c.Flags().Set("keep-raw", "true"))
	require.NoError(t, c.Flags().Set("clean-raw", "true"))

	err := runAgentAudit(c, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}
