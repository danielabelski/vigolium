package dbimport

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestMergeResults(t *testing.T) {
	results := []*Result{
		{
			RecordsImported: 10, FindingsTotal: 4, FindingsSaved: 3, FindingsSkipped: 1, ParseErrors: 1,
			SeverityCounts: map[string]int{"high": 2, "low": 1},
			SkippedTypes:   map[string]int{"note": 1},
			MergeStats:     &database.MergeStats{RecordsMerged: 10, FindingsMerged: 3, FindingsDeduped: 1, ScansMerged: 1},
		},
		nil, // nil entries are ignored
		{
			RecordsImported: 5, FindingsTotal: 2, FindingsSaved: 2,
			SeverityCounts: map[string]int{"high": 1},
			MergeStats:     &database.MergeStats{RecordsMerged: 5, FindingsMerged: 2, ScansMerged: 2, OASTMerged: 4},
		},
	}
	agg := MergeResults(results)
	if agg.RecordsImported != 15 || agg.FindingsTotal != 6 || agg.FindingsSaved != 5 || agg.FindingsSkipped != 1 || agg.ParseErrors != 1 {
		t.Fatalf("counters wrong: %+v", agg)
	}
	if agg.SeverityCounts["high"] != 3 || agg.SeverityCounts["low"] != 1 || agg.SkippedTypes["note"] != 1 {
		t.Fatalf("maps wrong: sev=%v skipped=%v", agg.SeverityCounts, agg.SkippedTypes)
	}
	if agg.MergeStats == nil {
		t.Fatal("expected summed MergeStats")
	}
	if agg.MergeStats.RecordsMerged != 15 || agg.MergeStats.FindingsMerged != 5 ||
		agg.MergeStats.FindingsDeduped != 1 || agg.MergeStats.ScansMerged != 3 || agg.MergeStats.OASTMerged != 4 {
		t.Fatalf("summed MergeStats wrong: %+v", agg.MergeStats)
	}

	// A source without MergeStats leaves the others summed; MergeResults itself
	// keeps MergeStats non-nil (the all-or-nothing display rule is the caller's).
	empty := MergeResults(nil)
	if empty.MergeStats != nil || empty.RecordsImported != 0 {
		t.Fatalf("empty aggregate should be zero-valued: %+v", empty)
	}
}

// newTestRepo spins up a throwaway in-memory SQLite repository, mirroring how
// the stateless JSONL loader bootstraps its scratch DB.
func newTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	ctx := context.Background()

	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = ":memory:"

	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	return database.NewRepository(db)
}

// jsonlEnvelope serializes a single {"type":...,"data":...} JSONL line.
func jsonlEnvelope(t *testing.T, typ string, data any) string {
	t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal data: %v", err)
	}
	line, err := json.Marshal(struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}{Type: typ, Data: raw})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(line)
}

// TestImportJSONLOversizedLine guards the regression that produced
// "bufio.Scanner: token too long": an http_record whose raw_response body is
// larger than the old 10MB scanner cap must still load. The reader-based loop
// grows to any line length.
func TestImportJSONLOversizedLine(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()

	// 12MB body → ~16MB once base64-encoded onto a single JSONL line, well past
	// the 10MB cap that used to fail.
	big := database.HTTPRecord{
		UUID:        "rec-big",
		Scheme:      "https",
		Hostname:    "example.com",
		Port:        443,
		Method:      "GET",
		Path:        "/big",
		URL:         "https://example.com/big",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "h-big",
		StatusCode:  200,
		HasResponse: true,
		RawResponse: bytes.Repeat([]byte("A"), 12*1024*1024),
	}
	small := database.HTTPRecord{
		UUID:        "rec-small",
		Scheme:      "https",
		Hostname:    "example.com",
		Port:        443,
		Method:      "GET",
		Path:        "/small",
		URL:         "https://example.com/small",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "h-small",
		StatusCode:  200,
	}

	// No trailing newline on the final line: exercises the EOF-without-delimiter path.
	stream := jsonlEnvelope(t, "http_record", big) + "\n" +
		jsonlEnvelope(t, "http_record", small)

	res, err := ImportJSONL(ctx, repo, strings.NewReader(stream), "", Options{})
	if err != nil {
		t.Fatalf("ImportJSONL on oversized line: %v", err)
	}
	if res.RecordsImported != 2 {
		t.Errorf("RecordsImported = %d, want 2", res.RecordsImported)
	}
	if res.ParseErrors != 0 {
		t.Errorf("ParseErrors = %d, want 0", res.ParseErrors)
	}
}

// newFileDBForTest creates a schema-ready, file-backed SQLite database at path.
// SQLite merges ATTACH a real source file, so an on-disk (not :memory:) database
// is required on both sides of the merge.
func newFileDBForTest(t *testing.T, path string) *database.DB {
	t.Helper()
	ctx := context.Background()
	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB(%s): %v", path, err)
	}
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema(%s): %v", path, err)
	}
	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults(%s): %v", path, err)
	}
	return db
}

// TestImportPathSQLiteMerge exercises the SQLite dispatch: a vigolium .sqlite
// result database passed to ImportPath must be detected by its magic header and
// merged (records + findings) into the destination, and a re-import must be a
// no-op (idempotent dedup on natural keys).
func TestImportPathSQLiteMerge(t *testing.T) {
	ctx := context.Background()

	// Source: a file-backed vigolium DB with one record + one finding, closed
	// before the merge so its WAL is flushed (mirrors the real scan→import flow).
	srcPath := filepath.Join(t.TempDir(), "external-scan.sqlite")
	srcDB := newFileDBForTest(t, srcPath)
	if _, err := srcDB.ExecContext(ctx, `INSERT INTO http_records
		(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash)
		VALUES ('rec-1', ?, 'https', 'example.com', 443, 'GET', '/', 'https://example.com/', 'HTTP/1.1', 'rh-1')`,
		database.DefaultProjectUUID); err != nil {
		t.Fatalf("seed source record: %v", err)
	}
	if _, err := srcDB.ExecContext(ctx, `INSERT INTO findings
		(project_uuid, http_record_uuids, module_id, module_name, severity, finding_hash)
		VALUES (?, '["rec-1"]', 'xss', 'XSS', 'high', 'fh-1')`,
		database.DefaultProjectUUID); err != nil {
		t.Fatalf("seed source finding: %v", err)
	}
	if err := srcDB.Close(); err != nil {
		t.Fatalf("close source: %v", err)
	}

	// Destination: a separate file-backed vigolium DB (the current/primary one).
	destDB := newFileDBForTest(t, filepath.Join(t.TempDir(), "dest.sqlite"))
	t.Cleanup(func() { _ = destDB.Close() })
	destRepo := database.NewRepository(destDB)

	res, err := ImportPath(ctx, destRepo, srcPath, database.DefaultProjectUUID, Options{})
	if err != nil {
		t.Fatalf("ImportPath(sqlite): %v", err)
	}
	if res.MergeStats == nil {
		t.Fatal("expected MergeStats to be set for a SQLite import")
	}
	if res.RecordsImported != 1 {
		t.Errorf("RecordsImported = %d, want 1", res.RecordsImported)
	}
	if res.FindingsSaved != 1 {
		t.Errorf("FindingsSaved = %d, want 1", res.FindingsSaved)
	}

	// Re-importing the same database merges nothing new.
	res2, err := ImportPath(ctx, destRepo, srcPath, database.DefaultProjectUUID, Options{})
	if err != nil {
		t.Fatalf("ImportPath(sqlite) re-import: %v", err)
	}
	if res2.RecordsImported != 0 || res2.FindingsSaved != 0 {
		t.Errorf("re-import merged new rows: records=%d findings=%d, want 0/0",
			res2.RecordsImported, res2.FindingsSaved)
	}
	if res2.MergeStats == nil || res2.MergeStats.FindingsDeduped != 1 {
		t.Errorf("re-import should dedup the 1 existing finding, got %+v", res2.MergeStats)
	}
}
