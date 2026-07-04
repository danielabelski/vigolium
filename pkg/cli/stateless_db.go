package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// globalGlobDB is the --glob-db flag: a glob pattern of local result files
// (.sqlite/.jsonl exports, audit folders, archives) that are merged into one
// throwaway in-memory DB and read with project scoping off. Registered on the
// read/query commands (finding, traffic, export) and on import. Providing it
// implies stateless-read semantics, so -S is optional alongside it.
var globalGlobDB string

// statelessReadRequested reports whether a read/query command should source its
// data from a standalone file rather than the shared project DB — true under
// -S/--stateless or whenever --glob-db is set (which implies stateless).
func statelessReadRequested() bool {
	return globalStateless || strings.TrimSpace(globalGlobDB) != ""
}

// openReadDB returns the database for read/query commands (traffic, finding).
// Under -S/--stateless (or --glob-db) it reads from the --db source directly (a
// JSONL export or a standalone SQLite file) or the merged --glob-db set;
// otherwise it returns the shared project DB.
func openReadDB() (*database.DB, error) {
	if statelessReadRequested() {
		return openStatelessDB()
	}
	return getDB()
}

// effectiveProjectUUID is the project filter for read/query commands: empty (no
// scoping, show every row) under -S/--stateless or --glob-db since a standalone
// file carries its own foreign project_uuid, otherwise the active project.
func effectiveProjectUUID() (string, error) {
	if statelessReadRequested() {
		return "", nil
	}
	return resolveProjectUUID()
}

// openStatelessDB resolves the -S/--stateless data source named by --db. The
// source may be either:
//
//   - a standalone .sqlite file — opened directly (read-only intent), or
//   - a {"type":...,"data":{...}} JSONL export (e.g. from
//     `vigolium scan --format jsonl`) — loaded into a throwaway in-memory
//     SQLite so every existing filter / sort / display path runs unchanged.
//
// Callers query with ProjectUUID="" (project scoping off), so all rows in the
// file are shown regardless of the project_uuid they were exported under.
func openStatelessDB() (*database.DB, error) {
	// --glob-db expands to many files merged into one in-memory DB; it takes
	// precedence over a single --db source.
	if pattern := strings.TrimSpace(globalGlobDB); pattern != "" {
		return openGlobDB(pattern)
	}
	if strings.TrimSpace(globalDB) == "" {
		return nil, fmt.Errorf("--stateless requires --db <file.jsonl|file.sqlite> or --glob-db <pattern>")
	}
	path := globalDB
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("--db %q: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("--db %q is a directory; expected a .jsonl export or .sqlite file", path)
	}

	if isJSONLSource(path) {
		return loadStatelessJSONL(path)
	}
	// Standalone SQLite: open directly via the shared connection cache (honours
	// --config); --db already points the cache at this file.
	return clicommon.GetDB(globalConfig, path)
}

// loadStatelessJSONL parses a {type,data} JSONL export into a fresh in-memory
// SQLite and returns it. The finding↔record linkage is preserved by the
// importer, so finding --raw / --with-records resolves linked records too.
func loadStatelessJSONL(path string) (*database.DB, error) {
	ctx := context.Background()

	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = ":memory:"

	db, err := database.NewDB(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create in-memory database: %w", err)
	}
	if err := db.CreateSchema(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize in-memory schema: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to open --db %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// projectUUID "" → rows import under the default project; the callers query
	// with ProjectUUID="" (no project filter) so everything in the file shows.
	res, err := dbimport.ImportJSONL(ctx, database.NewRepository(db), f, "", dbimport.Options{})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to load JSONL from %q: %w", path, err)
	}

	fmt.Fprintf(os.Stderr, "%s Stateless: loaded %d HTTP record(s) and %d finding(s) from %s\n",
		terminal.InfoSymbol(), res.RecordsImported, res.FindingsTotal, terminal.Cyan(filepath.Base(path)))

	// Cache it so the rest of the command (and closeDatabaseOnExit) reuse and
	// close this connection rather than opening the default project DB.
	clicommon.SetDBCache(db)
	return db, nil
}

// openGlobDB expands pattern to local result files and merges them all into a
// single throwaway in-memory SQLite DB, which callers query with project
// scoping off. Each match is imported by its own detected type via
// dbimport.ImportPath (SQLite→SQLite merge, JSONL export, audit folder, or
// archive), so a glob can mix formats. A match that fails to import is skipped
// with a warning rather than aborting the whole read. Returns an error when the
// pattern is invalid, matches nothing, or nothing could be loaded.
func openGlobDB(pattern string) (*database.DB, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid --glob-db pattern %q: %w", pattern, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("--glob-db %q matched no files", pattern)
	}

	ctx := context.Background()

	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = ":memory:"

	db, err := database.NewDB(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create in-memory database: %w", err)
	}
	if err := db.CreateSchema(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize in-memory schema: %w", err)
	}
	repo := database.NewRepository(db)

	// projectUUID "" → SQLite merges keep each row's original project and JSONL
	// rows import under the default project; callers query with ProjectUUID=""
	// (no project filter) so everything in every matched file shows.
	var loaded, totalRecords, totalFindings int
	for _, m := range matches {
		res, impErr := dbimport.ImportPath(ctx, repo, m, "", dbimport.Options{})
		if impErr != nil {
			fmt.Fprintf(os.Stderr, "%s --glob-db: skipped %s: %v\n", terminal.WarningSymbol(), terminal.Cyan(m), impErr)
			continue
		}
		loaded++
		totalRecords += res.RecordsImported
		totalFindings += res.FindingsTotal
	}
	if loaded == 0 {
		_ = db.Close()
		return nil, fmt.Errorf("--glob-db %q: none of the %d matched file(s) could be loaded", pattern, len(matches))
	}

	fmt.Fprintf(os.Stderr, "%s Stateless: merged %d file(s) — %d HTTP record(s), %d finding(s) — from %s\n",
		terminal.InfoSymbol(), loaded, totalRecords, totalFindings, terminal.Cyan(pattern))

	// Cache it so the rest of the command (and closeDatabaseOnExit) reuse and
	// close this connection rather than opening the default project DB.
	clicommon.SetDBCache(db)
	return db, nil
}

// openExportDB returns the database for `vigolium export`. It honors --glob-db
// (merge a glob of result files) and -S/--stateless (a single standalone --db
// source) so the export commands can read from ad-hoc files, falling back to the
// shared project DB. Export already reads whole-DB (project scoping off), so a
// standalone source needs no further project handling.
func openExportDB() (*database.DB, error) {
	if statelessReadRequested() {
		return openStatelessDB()
	}
	return getDB()
}

// isJSONLSource decides whether --db points at a JSONL export (true) or a
// SQLite database (false). It trusts a known extension, otherwise sniffs the
// file header: SQLite files begin with the magic string "SQLite format 3\0",
// while a JSONL export begins with '{'.
func isJSONLSource(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jsonl", ".ndjson":
		return true
	case ".sqlite", ".sqlite3", ".db":
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 16)
	n, _ := f.Read(buf)
	head := buf[:n]
	if database.HasSQLiteHeader(head) {
		return false
	}
	// First non-whitespace byte: '{' marks a JSON envelope line.
	trimmed := bytes.TrimLeft(head, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}
