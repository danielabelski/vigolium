package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
)

func TestGatherImportSources(t *testing.T) {
	dir := t.TempDir()
	// Create a few files to exercise the --glob-db expansion.
	for _, name := range []string{"scan-a.sqlite", "scan-b.sqlite", "other.db"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	a := filepath.Join(dir, "scan-a.sqlite")
	b := filepath.Join(dir, "scan-b.sqlite")

	t.Run("positional args only", func(t *testing.T) {
		got, err := gatherImportSources([]string{a, b}, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []string{a, b}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("glob only, sorted", func(t *testing.T) {
		got, err := gatherImportSources(nil, filepath.Join(dir, "scan-*.sqlite"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// filepath.Glob + explicit sort → deterministic lexical order.
		if want := []string{a, b}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("positional plus glob dedupes overlap and preserves order", func(t *testing.T) {
		// `a` appears both positionally and via the glob; it must appear once,
		// in its first (positional) position.
		got, err := gatherImportSources([]string{a}, filepath.Join(dir, "scan-*.sqlite"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []string{a, b}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("gcs alias normalized", func(t *testing.T) {
		got, err := gatherImportSources([]string{"gcs://proj/key.sqlite"}, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []string{"gs://proj/key.sqlite"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("no sources is an error", func(t *testing.T) {
		if _, err := gatherImportSources(nil, ""); err == nil {
			t.Fatal("expected an error when no sources are provided")
		}
	})

	t.Run("glob matching nothing is not an error", func(t *testing.T) {
		// A zero-match glob warns (to stderr) but, combined with a positional
		// arg, still yields the positional source rather than failing.
		got, err := gatherImportSources([]string{a}, filepath.Join(dir, "nomatch-*.sqlite"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []string{a}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("invalid glob pattern is an error", func(t *testing.T) {
		if _, err := gatherImportSources(nil, "["); err == nil {
			t.Fatal("expected an error for a malformed glob pattern")
		}
	})
}

func TestImportSourceFormat(t *testing.T) {
	cases := map[string]string{
		"scan.sqlite":             "sqlite",
		"scan.sqlite3":            "sqlite",
		"scan.db":                 "sqlite",
		"export.jsonl":            "jsonl",
		"export.ndjson":           "jsonl",
		"bundle.tar.gz":           "archive",
		"bundle.tgz":              "archive",
		"bundle.zip":              "archive",
		"audit-folder":            "folder",
		"gs://proj/key.sqlite":    "sqlite",
		"gs://proj/dump.jsonl":    "jsonl",
		"gs://proj/bundle.tar.gz": "archive",
		"weird.txt":               "other",
	}
	for in, want := range cases {
		if got := importSourceFormat(in); got != want {
			t.Errorf("importSourceFormat(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWarnMixedImportFormats(t *testing.T) {
	t.Run("sibling sqlite extensions are one format", func(t *testing.T) {
		kinds := warnMixedImportFormats([]string{"a.sqlite", "b.sqlite3", "c.db"})
		if len(kinds) != 1 || kinds[0] != "sqlite" {
			t.Fatalf("expected single sqlite kind, got %v", kinds)
		}
	})

	t.Run("sibling jsonl extensions are one format", func(t *testing.T) {
		kinds := warnMixedImportFormats([]string{"a.jsonl", "b.ndjson"})
		if len(kinds) != 1 || kinds[0] != "jsonl" {
			t.Fatalf("expected single jsonl kind, got %v", kinds)
		}
	})

	t.Run("mixed extensions detected in first-seen order", func(t *testing.T) {
		kinds := warnMixedImportFormats([]string{"a.jsonl", "b.sqlite", "c.jsonl"})
		if len(kinds) != 2 || kinds[0] != "jsonl" || kinds[1] != "sqlite" {
			t.Fatalf("expected [jsonl sqlite], got %v", kinds)
		}
	})
}

func TestAggregateImportResults(t *testing.T) {
	t.Run("all SQLite merges sum MergeStats", func(t *testing.T) {
		results := []*dbimport.Result{
			{
				RecordsImported: 10, FindingsSaved: 3, FindingsSkipped: 1, FindingsTotal: 4,
				SeverityCounts: map[string]int{"high": 2, "low": 1},
				MergeStats:     &database.MergeStats{RecordsMerged: 10, FindingsMerged: 3, FindingsDeduped: 1, ScansMerged: 1},
			},
			{
				RecordsImported: 5, FindingsSaved: 2, FindingsSkipped: 0, FindingsTotal: 2,
				SeverityCounts: map[string]int{"high": 1},
				MergeStats:     &database.MergeStats{RecordsMerged: 5, FindingsMerged: 2, ScansMerged: 2, OASTMerged: 4},
			},
		}
		agg := aggregateImportResults(results)
		if agg.RecordsImported != 15 || agg.FindingsSaved != 5 || agg.FindingsSkipped != 1 || agg.FindingsTotal != 6 {
			t.Fatalf("finding counters wrong: %+v", agg)
		}
		if agg.SeverityCounts["high"] != 3 || agg.SeverityCounts["low"] != 1 {
			t.Fatalf("severity counts wrong: %v", agg.SeverityCounts)
		}
		if agg.MergeStats == nil {
			t.Fatal("expected MergeStats to be set when all sources are merges")
		}
		if agg.MergeStats.RecordsMerged != 15 || agg.MergeStats.FindingsMerged != 5 ||
			agg.MergeStats.FindingsDeduped != 1 || agg.MergeStats.ScansMerged != 3 || agg.MergeStats.OASTMerged != 4 {
			t.Fatalf("merged stats wrong: %+v", agg.MergeStats)
		}
	})

	t.Run("mixed sources leave MergeStats nil", func(t *testing.T) {
		results := []*dbimport.Result{
			{RecordsImported: 10, MergeStats: &database.MergeStats{RecordsMerged: 10}},
			{RecordsImported: 0, FindingsSaved: 4, FindingsTotal: 4}, // audit/JSONL — no MergeStats
		}
		agg := aggregateImportResults(results)
		if agg.MergeStats != nil {
			t.Fatalf("expected nil MergeStats for mixed sources, got %+v", agg.MergeStats)
		}
		if agg.RecordsImported != 10 || agg.FindingsSaved != 4 {
			t.Fatalf("counters wrong for mixed aggregate: %+v", agg)
		}
	})
}
