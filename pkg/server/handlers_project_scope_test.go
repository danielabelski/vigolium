package server

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// insertRecordReturning inserts an HTTP record under projectUUID and returns its
// UUID so the by-uuid detail/delete endpoints can be exercised.
func insertRecordReturning(t *testing.T, db *database.DB, projectUUID string) string {
	t.Helper()
	uuid := "rec-" + randSuffix()
	rec := &database.HTTPRecord{
		UUID:        uuid,
		ProjectUUID: projectUUID,
		Scheme:      "https",
		Hostname:    "example.test",
		Port:        443,
		Method:      "GET",
		Path:        "/",
		URL:         "https://example.test/",
		HTTPVersion: "HTTP/1.1",
		RequestHash: "hash-" + randSuffix(),
	}
	if _, err := db.NewInsert().Model(rec).Exec(context.Background()); err != nil {
		t.Fatalf("insert record: %v", err)
	}
	return uuid
}

// TestPointEndpoints_ProjectScoping verifies the by-id/by-uuid detail and
// mutation endpoints refuse to read, mutate, or delete rows outside the
// request's active project. Routes are registered without the project
// middleware, so getProjectUUID resolves to DefaultProjectUUID; a row seeded
// under a different project must be invisible (404) — otherwise an operator
// scoped to one engagement could touch another's data via a raw id.
func TestPointEndpoints_ProjectScoping(t *testing.T) {
	const otherProject = "11111111-1111-1111-1111-111111111111"

	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)

	otherFinding := insertFindingReturning(t, db, otherProject)
	otherOAST := insertOAST(t, db, otherProject)
	otherScan := insertScan(t, db, repo, otherProject)
	otherRecordUUID := insertRecordReturning(t, db, otherProject)

	app := fiber.New()
	app.Get("/api/findings/:id", h.findingsHandler().HandleGetFinding)
	app.Put("/api/findings/:id/status", h.findingsHandler().HandleUpdateFindingStatus)
	app.Delete("/api/findings/:id", h.findingsHandler().HandleDeleteFinding)
	app.Get("/api/http-records/:uuid", h.HandleGetRecord)
	app.Delete("/api/http-records/:uuid", h.HandleDeleteRecord)
	app.Get("/api/oast-interactions/:id", h.HandleGetOASTInteraction)
	app.Delete("/api/oast-interactions/:id", h.HandleDeleteOASTInteraction)
	app.Get("/api/scans/:uuid", h.HandleGetScan)

	fid := strconv.FormatInt(otherFinding, 10)
	oid := strconv.FormatInt(otherOAST, 10)

	cases := []struct {
		name, method, path, body string
	}{
		{"get finding", http.MethodGet, "/api/findings/" + fid, ""},
		{"update finding status", http.MethodPut, "/api/findings/" + fid + "/status", `{"status":"triaged"}`},
		{"delete finding", http.MethodDelete, "/api/findings/" + fid, ""},
		{"get record", http.MethodGet, "/api/http-records/" + otherRecordUUID, ""},
		{"delete record", http.MethodDelete, "/api/http-records/" + otherRecordUUID, ""},
		{"get oast", http.MethodGet, "/api/oast-interactions/" + oid, ""},
		{"delete oast", http.MethodDelete, "/api/oast-interactions/" + oid, ""},
		{"get scan", http.MethodGet, "/api/scans/" + otherScan, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name+" cross-project → 404", func(t *testing.T) {
			status, body := doReq(t, app, tc.method, tc.path, tc.body, nil)
			if status != http.StatusNotFound {
				t.Errorf("status = %d, want 404; body %s", status, body)
			}
		})
	}

	// Sanity: the same resource shape IS reachable when it lives in the request's
	// (default) project, so the 404s above are scoping, not a broken route.
	sameFinding := insertFindingReturning(t, db, database.DefaultProjectUUID)
	if status, body := doReq(t, app, http.MethodGet, "/api/findings/"+strconv.FormatInt(sameFinding, 10), "", nil); status != http.StatusOK {
		t.Errorf("same-project finding status = %d, want 200; body %s", status, body)
	}
}
