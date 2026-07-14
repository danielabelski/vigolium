package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

// seedPriorRecord inserts one http_record under project with the given shape.
func seedPriorRecord(t *testing.T, db *database.DB, project, uuid, method, host, path string, status int, source string) {
	t.Helper()
	_, err := db.NewInsert().Model(&database.HTTPRecord{
		UUID:        uuid,
		ProjectUUID: project,
		Source:      source,
		Scheme:      "https",
		Hostname:    host,
		Port:        443,
		Method:      method,
		Path:        path,
		URL:         "https://" + host + path,
		StatusCode:  status,
		HTTPVersion: "HTTP/1.1",
		RequestHash: "rh-" + uuid,
		RawRequest:  []byte(method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"),
	}).Exec(context.Background())
	require.NoError(t, err)
}

func seedPriorFinding(t *testing.T, db *database.DB, project, suffix, severity string) {
	t.Helper()
	require.NoError(t, database.NewRepository(db).SaveFindingDirect(context.Background(), &database.Finding{
		ProjectUUID:     project,
		HTTPRecordUUIDs: []string{"rec-" + suffix},
		ModuleID:        "mod-" + suffix,
		ModuleName:      "Issue " + suffix,
		Severity:        severity,
		Confidence:      "firm",
		FindingHash:     "fh-" + suffix,
		URL:             "https://app.example/" + suffix,
		Hostname:        "app.example",
	}))
}

func TestBuildPriorContextBrief(t *testing.T) {
	ctx := context.Background()
	const project = "proj-prior"
	db := newExportTestDB(t)
	repo := database.NewRepository(db)

	// Traffic across two hosts + two sources (incl. burp), and three findings.
	seedPriorRecord(t, db, project, "r1", "GET", "app.example", "/api/users/1", 200, "burp")
	seedPriorRecord(t, db, project, "r2", "GET", "app.example", "/api/users/2", 200, "burp")
	seedPriorRecord(t, db, project, "r3", "POST", "app.example", "/api/login", 200, "scanner")
	seedPriorRecord(t, db, project, "r4", "GET", "admin.example", "/admin/dashboard", 403, "burp")
	seedPriorFinding(t, db, project, "idor", "high")
	seedPriorFinding(t, db, project, "xss", "medium")
	seedPriorFinding(t, db, project, "info1", "info")

	t.Run("full brief has totals, table, findings, pointer", func(t *testing.T) {
		out, nRec, nFind := buildPriorContextBrief(ctx, repo, project, priorCtxAuto)
		require.Equal(t, 4, nRec, "returned record count")
		require.Equal(t, 3, nFind, "returned finding count")
		for _, want := range []string{
			"Prior context",
			"4 records",
			"2 hosts",
			"Findings: 3 (1 High, 1 Medium, 1 Info)",
			"Sources:",
			"burp (3)",
			"Top endpoints",
			"/api/login",
			"Open findings",
			"[High] Issue idor",
			"query_records",
		} {
			require.Contains(t, out, want, "full brief missing %q\n---\n%s", want, out)
		}
	})

	t.Run("summary is a one-liner without the table", func(t *testing.T) {
		out, _, _ := buildPriorContextBrief(ctx, repo, project, priorCtxSummary)
		require.Contains(t, out, "4 records")
		require.Contains(t, out, "query_records")
		require.NotContains(t, out, "Top endpoints", "summary must not render the endpoint table")
		require.NotContains(t, out, "Open findings")
	})

	t.Run("off renders nothing", func(t *testing.T) {
		out, _, _ := buildPriorContextBrief(ctx, repo, project, priorCtxOff)
		require.Empty(t, out)
	})

	t.Run("empty project renders nothing", func(t *testing.T) {
		for _, mode := range []string{priorCtxAuto, priorCtxSummary} {
			out, _, _ := buildPriorContextBrief(ctx, repo, "proj-empty", mode)
			require.Empty(t, out)
		}
	})
}

// TestBuildPriorContextBrief_Bounded verifies the endpoint table stays capped
// even when the project holds far more distinct endpoints than the cap, and
// that the header advertises the true total ("N of M").
func TestBuildPriorContextBrief_Bounded(t *testing.T) {
	ctx := context.Background()
	const project = "proj-bounded"
	db := newExportTestDB(t)
	repo := database.NewRepository(db)

	const total = priorContextEndpointCap + 15
	for i := 0; i < total; i++ {
		seedPriorRecord(t, db, project, fmt.Sprintf("b%d", i), "GET", "app.example",
			fmt.Sprintf("/api/resource/%d", i), 200, "burp")
	}

	out, nRec, _ := buildPriorContextBrief(ctx, repo, project, priorCtxAuto)
	require.Equal(t, total, nRec, "returned record count")
	// Header must advertise the true distinct-endpoint total.
	require.Contains(t, out, fmt.Sprintf("of %d", total))
	// But only the cap number of endpoint rows are rendered.
	rows := strings.Count(out, "  GET  ")
	require.LessOrEqual(t, rows, priorContextEndpointCap,
		"endpoint rows must be capped at %d, got %d", priorContextEndpointCap, rows)
}

func TestValidatePriorContextMode(t *testing.T) {
	for _, in := range []string{"", "auto", "AUTO", "full", "summary", "off"} {
		_, err := validatePriorContextMode(in)
		require.NoError(t, err, "mode %q should be valid", in)
	}
	// "" and "full" both normalize to auto (full is a back-compat synonym).
	for _, in := range []string{"", "auto", "full", "FULL"} {
		got, _ := validatePriorContextMode(in)
		require.Equal(t, priorCtxAuto, got, "%q should normalize to auto", in)
	}
	if _, err := validatePriorContextMode("bogus"); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}
