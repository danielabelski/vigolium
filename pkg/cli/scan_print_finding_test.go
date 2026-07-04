package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

// --print-finding renders the run's findings to stdout as Markdown after the
// scan, scoped to this scan by project + scan UUID, reusing the same renderer as
// `vigolium finding --markdown`.
func TestMaybePrintScanFindings(t *testing.T) {
	ctx := context.Background()
	const project = "proj-print"
	t.Cleanup(func() { scanPrintFinding = false })

	seed := func(t *testing.T, db *database.DB, scanUUID, suffix string) {
		t.Helper()
		require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, &database.Finding{
			ProjectUUID:     project,
			ScanUUID:        scanUUID,
			HTTPRecordUUIDs: []string{"rec-" + suffix},
			ModuleID:        "mod-" + suffix,
			ModuleName:      "Module " + suffix,
			Severity:        "high",
			Confidence:      "firm",
			FindingHash:     "hash-" + suffix,
			URL:             "http://" + suffix + ".example/",
			Hostname:        suffix + ".example",
		}))
		_, err := db.NewInsert().Model(&database.HTTPRecord{
			UUID:        "rec-" + suffix,
			ProjectUUID: project,
			Scheme:      "http",
			Hostname:    suffix + ".example",
			Port:        80,
			Method:      "GET",
			Path:        "/",
			URL:         "http://" + suffix + ".example/",
			HTTPVersion: "HTTP/1.1",
			RequestHash: "rhash-" + suffix,
			RawRequest:  []byte("GET / HTTP/1.1\r\nHost: " + suffix + ".example\r\n\r\n"),
		}).Exec(ctx)
		require.NoError(t, err)
	}

	t.Run("off is a no-op", func(t *testing.T) {
		db := newExportTestDB(t)
		seed(t, db, "scan-a", "a")
		scanPrintFinding = false
		out := captureStdout(t, func() { maybePrintScanFindings(ctx, db, project, "scan-a") })
		require.Empty(t, strings.TrimSpace(out), "flag off must print nothing")
	})

	t.Run("renders markdown scoped to the scan UUID", func(t *testing.T) {
		db := newExportTestDB(t)
		seed(t, db, "scan-a", "a")
		seed(t, db, "scan-b", "b") // different scan — must be excluded
		scanPrintFinding = true
		out := captureStdout(t, func() { maybePrintScanFindings(ctx, db, project, "scan-a") })

		require.Contains(t, out, "Module a", "must render this scan's finding")
		require.Contains(t, out, "```http", "must render the request/response evidence block")
		require.NotContains(t, out, "Module b", "must not render a different scan's finding")
	})

	t.Run("no findings prints nothing", func(t *testing.T) {
		db := newExportTestDB(t)
		scanPrintFinding = true
		out := captureStdout(t, func() { maybePrintScanFindings(ctx, db, project, "scan-empty") })
		require.Empty(t, strings.TrimSpace(out), "a scan with no findings must print nothing")
	})

	t.Run("nil db is a no-op", func(t *testing.T) {
		scanPrintFinding = true
		out := captureStdout(t, func() { maybePrintScanFindings(ctx, nil, project, "scan-a") })
		require.Empty(t, strings.TrimSpace(out))
	})
}
