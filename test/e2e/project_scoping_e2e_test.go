//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// End-to-end coverage for project scoping of scan output, guarding the two
// defects reported against the 0.3 line:
//
//  1. Every core.ExecutorConfig literal omitted ProjectUUID, so the executor's
//     records and ALL of its findings were written to the DEFAULT project even
//     when the scan ran under --project-name. The scan summary, the exports and
//     the record feed all filter by the scan's own project, so a healthy scan
//     that streamed dozens of findings reported "Findings: no issues found" —
//     and when discovery/spidering were skipped the assessment phase had no
//     visible records at all and reported "0 items".
//
//  2. `vigolium project create --db <new file>` failed with "no such table:
//     projects" because the project subcommands opened the database without
//     ever creating the schema, so a clean install could not bootstrap itself.
//
// These drive the real CLI binary against a local httptest server, so no Docker
// is required.

// projectScopingTarget serves a page that reliably trips passive modules
// (missing security headers, a leaked server banner, a form without CSRF
// protection) so the scan has something to find without needing a full
// vulnerable app.
func projectScopingTarget(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "Apache/2.4.29 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.2.24")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html>
<html><head><title>project scoping fixture</title></head>
<body>
  <h1>fixture</h1>
  <form method="POST" action="/login">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="submit" value="Log in">
  </form>
  <a href="/about">about</a>
</body></html>`))
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "Apache/2.4.29 (Ubuntu)")
		_, _ = w.Write([]byte(`<html><body>about page</body></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// openSQLiteDB opens the SQLite database at path for direct assertions,
// reusing the production defaults so the test never drifts from how the CLI
// itself opens a database (this is the same idiom as pkg/cli/stateless_db.go).
func openSQLiteDB(t *testing.T, path string) *database.DB {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// countRowsForProject returns how many rows of the given table belong to
// projectUUID.
func countRowsForProject(t *testing.T, db *database.DB, table, projectUUID string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table+" WHERE project_uuid = ?", projectUUID).Scan(&n))
	return n
}

// runVigolium runs the CLI with an isolated HOME so first-run initialization
// (wordlist materialization, ~/.vigolium seeding) never races other tests or
// picks up the developer's own config.
func runVigolium(t *testing.T, bin, home string, timeout time.Duration, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		// Must be empty: an inherited VIGOLIUM_PROJECT would silently decide
		// the very scoping this test is asserting.
		"VIGOLIUM_PROJECT=",
		"VIGOLIUM_PROJECT_UUID=",
		"VIGOLIUM_DB_PATH=",
	)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return terminal.StripANSI(out.String()), err
}

// TestProjectCreateBootstrapsSchemaOnFreshDB guards defect 2. `project create`
// is routinely the FIRST command to touch a brand-new --db file, so unlike most
// read paths it cannot assume some earlier command already ran CreateSchema.
// The regression made a clean install impossible: creating a project only
// worked against a database that had been populated by some other command (in
// practice, by cloning an existing one).
func TestProjectCreateBootstrapsSchemaOnFreshDB(t *testing.T) {
	bin := buildVigoliumBinary(t)
	home := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "fresh.sqlite")

	// Precondition: the file must not exist yet — that is the whole point.
	_, statErr := os.Stat(dbPath)
	require.True(t, os.IsNotExist(statErr), "test fixture must start with no database file")

	out, err := runVigolium(t, bin, home, 60*time.Second,
		"project", "create", "e2e-fresh", "--db", dbPath)
	require.NoErrorf(t, err, "project create on a fresh DB must succeed:\n%s", out)
	assert.NotContains(t, out, "no such table",
		"project create must bootstrap the schema rather than failing on a missing table")

	// The project must be readable back through the CLI, which proves the row
	// was really committed and not merely reported.
	listOut, err := runVigolium(t, bin, home, 60*time.Second, "project", "list", "--db", dbPath)
	require.NoErrorf(t, err, "project list on the new DB must succeed:\n%s", listOut)
	assert.Contains(t, listOut, "e2e-fresh")
}

// scopedScan is the result of runScopedScan: the database the scan wrote to,
// the project it ran under, its console output, and a runCLI hook for follow-up
// commands against the same database and project.
type scopedScan struct {
	db          *database.DB
	projectUUID string
	projectName string
	out         string
	runCLI      func(t *testing.T, args ...string) (string, error)
}

// runScopedScan creates projectName on a fresh database and scans the fixture
// target under it. skipPhases is the --skip list, which is the only thing the
// two scan tests below vary.
func runScopedScan(t *testing.T, projectName, skipPhases string) scopedScan {
	t.Helper()
	bin := buildVigoliumBinary(t)
	home := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "scoped.sqlite")
	srv := projectScopingTarget(t)

	createOut, err := runVigolium(t, bin, home, 60*time.Second,
		"project", "create", projectName, "--db", dbPath)
	require.NoErrorf(t, err, "project create failed:\n%s", createOut)

	db := openSQLiteDB(t, dbPath)
	var projectUUID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		"SELECT uuid FROM projects WHERE name = ?", projectName).Scan(&projectUUID))
	require.NotEmpty(t, projectUUID)
	require.NotEqual(t, database.DefaultProjectUUID, projectUUID,
		"fixture must use a NON-default project or the bug is unobservable")

	scanOut, err := runVigolium(t, bin, home, 5*time.Minute,
		"scan",
		"-t", srv.URL,
		"--db", dbPath,
		"--project-name", projectName,
		"--skip", skipPhases,
		"--scanning-max-duration", "60s",
		"--skip-dependency-check",
	)
	require.NoErrorf(t, err, "scan failed:\n%s", scanOut)

	return scopedScan{
		db:          db,
		projectUUID: projectUUID,
		projectName: projectName,
		out:         scanOut,
		runCLI: func(t *testing.T, args ...string) (string, error) {
			t.Helper()
			return runVigolium(t, bin, home, 60*time.Second,
				append(args, "--db", dbPath, "--project-name", projectName)...)
		},
	}
}

// TestScanUnderNamedProjectStampsThatProject guards defect 1, the data-integrity
// half of the report. A scan run under --project-name must write its records
// AND its findings to that project; anything stamped with the default project is
// invisible to the scan that produced it.
func TestScanUnderNamedProjectStampsThatProject(t *testing.T) {
	scan := runScopedScan(t, "e2e-scoped", "external-harvest,spidering,known-issue-scan")
	db, projectUUID, scanOut := scan.db, scan.projectUUID, scan.out

	// Records: the scan's own project must own them. Before the fix the
	// executor-written rows (source "scanner") landed under the default project,
	// leaving the assessment feed — which pins project_uuid to the scan's
	// project — with nothing to hand the modules.
	scopedRecords := countRowsForProject(t, db, "http_records", projectUUID)
	defaultRecords := countRowsForProject(t, db, "http_records", database.DefaultProjectUUID)
	assert.Positivef(t, scopedRecords,
		"expected http_records under the scan's project %s, got 0 (default project holds %d)\n%s",
		projectUUID, defaultRecords, scanOut)
	assert.Zerof(t, defaultRecords,
		"no record may be stamped with the default project when the scan ran under %s\n%s",
		projectUUID, scanOut)

	// Findings: the half that produced the reported "no issues found" on a scan
	// that had just streamed findings to the console.
	scopedFindings := countRowsForProject(t, db, "findings", projectUUID)
	defaultFindings := countRowsForProject(t, db, "findings", database.DefaultProjectUUID)
	assert.Positivef(t, scopedFindings,
		"expected findings under the scan's project %s, got 0 (default project holds %d)\n%s",
		projectUUID, defaultFindings, scanOut)
	assert.Zerof(t, defaultFindings,
		"no finding may be stamped with the default project when the scan ran under %s\n%s",
		projectUUID, scanOut)

	// The console summary is what the reporter actually saw, so assert on it
	// too: a scan whose findings are misfiled prints "no issues found".
	assert.NotContains(t, scanOut, "no issues found",
		"scan summary must report the findings it stored under the scan's project")

	// And the findings must be readable back under that project.
	findOut, err := scan.runCLI(t, "finding", "list")
	require.NoErrorf(t, err, "finding list failed:\n%s", findOut)
	assert.NotContains(t, findOut, "No findings",
		"findings stored by the scan must be visible to a project-scoped read")
}

// TestScanUnderNamedProjectAssessesSeededRecords is the reporter's own
// reduction, and the sharpest form of the bug. With spidering and discovery
// skipped the ONLY record is the one the Seed phase writes through the
// executor, so if that record is stamped with the wrong project the assessment
// phase has literally nothing to read: it reported "0 items" while the database
// showed the seed row sitting in the default project and the scan's cursor
// still at Go's zero value.
func TestScanUnderNamedProjectAssessesSeededRecords(t *testing.T) {
	scan := runScopedScan(t, "e2e-seed", "external-harvest,spidering,discovery,known-issue-scan")
	db, projectUUID, scanOut := scan.db, scan.projectUUID, scan.out

	assert.Positivef(t, countRowsForProject(t, db, "http_records", projectUUID),
		"the seeded CLI target must be stored under the scan's project\n%s", scanOut)

	// The round summary is the reporter's headline symptom: "round 1 — 0 items".
	assert.NotContains(t, scanOut, "0 items in",
		"DynamicAssessment must consume the seeded record, not report 0 items\n"+scanOut)

	// The scan cursor is the DB-level evidence they collected. It only advances
	// when a record is actually acknowledged, so a zero cursor on a finished
	// scan means nothing was ever fed to the modules.
	var cursorUUID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		"SELECT COALESCE(cursor_uuid, '') FROM scans WHERE project_uuid = ? ORDER BY started_at DESC LIMIT 1",
		projectUUID).Scan(&cursorUUID))
	assert.NotEmptyf(t, cursorUUID,
		"scan cursor must advance past at least one record; an empty cursor_uuid means the assessment phase read nothing\n%s",
		scanOut)
}
