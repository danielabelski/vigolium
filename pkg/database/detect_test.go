package database

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsSQLiteFile confirms header-based detection: a real SQLite database is
// recognized regardless of extension, while a JSONL export and a too-short file
// are not.
func TestIsSQLiteFile(t *testing.T) {
	// A genuine SQLite database, named with a non-.sqlite extension.
	db, dbPath := newFileDB(t, "scan.db")
	_ = db.Close()
	if ok, err := IsSQLiteFile(dbPath); err != nil || !ok {
		t.Errorf("IsSQLiteFile(%s) = %v, %v; want true, nil", dbPath, ok, err)
	}

	// A JSONL export must not be mistaken for a database.
	jsonlPath := filepath.Join(t.TempDir(), "export.jsonl")
	if err := os.WriteFile(jsonlPath, []byte(`{"type":"finding","data":{}}`+"\n"), 0o644); err != nil {
		t.Fatalf("write jsonl: %v", err)
	}
	if ok, err := IsSQLiteFile(jsonlPath); err != nil || ok {
		t.Errorf("IsSQLiteFile(%s) = %v, %v; want false, nil", jsonlPath, ok, err)
	}

	// A tiny file (shorter than the 16-byte header) is not a database.
	tinyPath := filepath.Join(t.TempDir(), "tiny.txt")
	if err := os.WriteFile(tinyPath, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write tiny: %v", err)
	}
	if ok, err := IsSQLiteFile(tinyPath); err != nil || ok {
		t.Errorf("IsSQLiteFile(tiny) = %v, %v; want false, nil", ok, err)
	}
}

// TestHasSQLiteHeader covers the byte-level check used by callers that already
// hold a file's leading bytes (the stateless --db reader).
func TestHasSQLiteHeader(t *testing.T) {
	if !HasSQLiteHeader([]byte("SQLite format 3\x00extra")) {
		t.Error("HasSQLiteHeader = false for a valid header")
	}
	if HasSQLiteHeader([]byte(`{"type":"finding"}`)) {
		t.Error("HasSQLiteHeader = true for a JSON line")
	}
	if HasSQLiteHeader([]byte("SQLite")) {
		t.Error("HasSQLiteHeader = true for a truncated prefix")
	}
}
