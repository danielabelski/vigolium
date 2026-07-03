package database

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// sqliteFileHeader is the 16-byte magic prefix every SQLite 3 database file
// begins with ("SQLite format 3\000"). It is the single source of truth for
// SQLite-file detection, shared by MergeSQLiteFile's importers and the
// stateless --db reader.
var sqliteFileHeader = []byte("SQLite format 3\x00")

// HasSQLiteHeader reports whether b begins with the SQLite 3 file magic. Callers
// that already hold the leading bytes of a file use this to avoid a second read.
func HasSQLiteHeader(b []byte) bool {
	return bytes.HasPrefix(b, sqliteFileHeader)
}

// IsSQLiteFile reports whether the file at path is a SQLite 3 database, detected
// by its magic header rather than its extension — so a .sqlite/.sqlite3/.db or a
// bare filename all resolve correctly. Files shorter than the header, or with
// any other leading bytes (e.g. a JSONL export), read as not-SQLite; a genuine
// open/read error is surfaced.
func IsSQLiteFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, len(sqliteFileHeader))
	if _, err := io.ReadFull(f, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil // too small to be a SQLite database
		}
		return false, fmt.Errorf("read header of %s: %w", path, err)
	}
	return HasSQLiteHeader(header), nil
}
