package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// insertRecordCorpus saves a record with a controllable path, request header
// value (X-Test) and response body so the search/exclusion corpus can be
// exercised distinctly per column.
func insertRecordCorpus(t *testing.T, repo *Repository, path, header, respBody string) string {
	t.Helper()
	ctx := context.Background()
	raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: h.example.com\r\nX-Test: %s\r\n\r\n", path, header)
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + respBody))
	rr = rr.WithResponse(resp)
	u, err := repo.SaveRecord(ctx, rr, "test", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}
	return u
}

// TestQueryBuilder_SearchTermsCorpus proves --search now spans the full
// request/response corpus, not just URL/path: a term present only in the
// response body still matches.
func TestQueryBuilder_SearchTermsCorpus(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecordCorpus(t, repo, "/alpha", "plain", "hello world")            // no "secret"
	insertRecordCorpus(t, repo, "/beta", "plain", "secret token here")       // secret in body only
	insertRecordCorpus(t, repo, "/gamma-secret", "plain", "nothing special") // secret in path only

	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, SearchTerms: []string{"secret"}})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("search 'secret': got %d records, want 2 (body match + path match)", len(recs))
	}
}

// TestQueryBuilder_ExcludeTerms covers the inverse of --search: a record is
// dropped when ANY exclude term appears in url/path or the raw corpus, and
// multiple exclude terms AND-combine.
func TestQueryBuilder_ExcludeTerms(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecordCorpus(t, repo, "/alpha", "plain", "hello world")      // keep
	insertRecordCorpus(t, repo, "/beta", "plain", "secret token here") // secret in body
	insertRecordCorpus(t, repo, "/gamma-secret", "plain", "nothing")   // secret in path
	insertRecordCorpus(t, repo, "/delta", "plain", "hush hush")        // matches 'hush'

	// Single exclude term drops both the body and path matches.
	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, ExcludeTerms: []string{"secret"}})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("exclude 'secret': got %d records, want 2 (alpha + delta)", len(recs))
	}
	for _, r := range recs {
		if r.Path == "/beta" || r.Path == "/gamma-secret" {
			t.Errorf("exclude 'secret' leaked %q", r.Path)
		}
	}

	// Two exclude terms AND-combine: drop anything matching 'secret' OR 'hush'.
	qb = NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, ExcludeTerms: []string{"secret", "hush"}})
	recs, err = qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 1 || recs[0].Path != "/alpha" {
		t.Fatalf("exclude 'secret'+'hush': got %d (%v), want only /alpha", len(recs), recs)
	}
}

// TestQueryBuilder_SearchAndExcludeCombine confirms --search and
// --exclude-search compose (positive narrows, negative subtracts).
func TestQueryBuilder_SearchAndExcludeCombine(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecordCorpus(t, repo, "/api/users", "plain", "ok")            // api, no health
	insertRecordCorpus(t, repo, "/api/health", "plain", "ok")           // api + health in path
	insertRecordCorpus(t, repo, "/api/orders", "plain", "health check") // api + health in body
	insertRecordCorpus(t, repo, "/static/app.js", "plain", "ok")        // not api

	qb := NewQueryBuilder(db, QueryFilters{
		ProjectUUID:  DefaultProjectUUID,
		SearchTerms:  []string{"api"},
		ExcludeTerms: []string{"health"},
	})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 1 || recs[0].Path != "/api/users" {
		t.Fatalf("search api + exclude health: got %d (%v), want only /api/users", len(recs), recs)
	}
}

// TestQueryBuilder_ExcludeKeepsNullCorpus is the NULL-guard regression: a
// response-less record (raw_response NULL) whose url/path does not match the
// exclude term must be KEPT. A bare NOT(... LIKE ...) without COALESCE would
// evaluate to NULL and wrongly drop it.
func TestQueryBuilder_ExcludeKeepsNullCorpus(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// Request-only record: no response, so raw_response is NULL.
	raw := "GET /plain HTTP/1.1\r\nHost: h.example.com\r\n\r\n"
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	if _, err := repo.SaveRecord(ctx, rr, "test", DefaultProjectUUID); err != nil {
		t.Fatalf("SaveRecord (request-only): %v", err)
	}

	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, ExcludeTerms: []string{"secret"}})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 1 || recs[0].Path != "/plain" {
		t.Fatalf("exclude with NULL corpus dropped a non-matching record: got %d (%v), want /plain kept", len(recs), recs)
	}
}

// TestQueryBuilder_ExcludeHeaderBody covers --exclude-header/--exclude-body,
// which drop records whose raw request/response corpus contains the term.
func TestQueryBuilder_ExcludeHeaderBody(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	insertRecordCorpus(t, repo, "/a", "keepme", "clean body")     // keep
	insertRecordCorpus(t, repo, "/b", "dropheader", "clean body") // header marker
	insertRecordCorpus(t, repo, "/c", "keepme", "dropbody here")  // body marker

	// exclude-header drops the record with the header marker.
	qb := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, ExcludeHeaderSearch: "dropheader"})
	recs, err := qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("exclude-header: got %d, want 2 (b dropped)", len(recs))
	}
	for _, r := range recs {
		if r.Path == "/b" {
			t.Errorf("exclude-header leaked /b")
		}
	}

	// exclude-body drops the record with the body marker.
	qb = NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, ExcludeBodySearch: "dropbody"})
	recs, err = qb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("exclude-body: got %d, want 2 (c dropped)", len(recs))
	}
	for _, r := range recs {
		if r.Path == "/c" {
			t.Errorf("exclude-body leaked /c")
		}
	}
}

// saveFindingWithDesc saves a finding with a controllable module id/name and
// description, optionally linked to HTTP records.
func saveFindingWithDesc(t *testing.T, repo *Repository, moduleID, desc string, recordUUIDs ...string) {
	t.Helper()
	f := &Finding{
		ProjectUUID:     DefaultProjectUUID,
		ModuleID:        moduleID,
		ModuleName:      moduleID,
		Description:     desc,
		Severity:        SeverityHigh,
		Confidence:      "firm",
		FindingHash:     uuid.New().String(),
		Status:          StatusTriaged,
		HTTPRecordUUIDs: recordUUIDs,
	}
	if err := repo.SaveFindingDirect(context.Background(), f); err != nil {
		t.Fatalf("SaveFindingDirect: %v", err)
	}
}

// TestFindingsQueryBuilder_ExcludeTerms covers finding --exclude-search over
// the finding's own fields (module metadata + description).
func TestFindingsQueryBuilder_ExcludeTerms(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	saveFindingWithDesc(t, repo, "sqli", "SQL injection in login form")
	saveFindingWithDesc(t, repo, "xss", "reflected xss in search")
	saveFindingWithDesc(t, repo, "csrf", "missing csrf token")

	// Positive search over description still works (broadened, but description-only
	// findings match).
	fqb := NewFindingsQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, SearchTerms: []string{"injection"}})
	found, err := fqb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(found) != 1 || found[0].ModuleID != "sqli" {
		t.Fatalf("search 'injection': got %d (%v), want only sqli", len(found), found)
	}

	// Exclude by module id drops that finding.
	fqb = NewFindingsQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, ExcludeTerms: []string{"xss"}})
	found, err = fqb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("exclude 'xss': got %d, want 2", len(found))
	}
	for _, f := range found {
		if f.ModuleID == "xss" {
			t.Errorf("exclude 'xss' leaked the xss finding")
		}
	}
}

// TestFindingsQueryBuilder_ExcludeLinkedRecord covers --exclude-search and
// --exclude-body reaching a finding's linked HTTP records via NOT EXISTS.
func TestFindingsQueryBuilder_ExcludeLinkedRecord(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	recClean := insertRecordCorpus(t, repo, "/login", "plain", "welcome")
	recMarked := insertRecordCorpus(t, repo, "/admin", "plain", "DROPTOKEN in response")

	saveFindingWithDesc(t, repo, "mod-a", "finding on clean record", recClean)
	saveFindingWithDesc(t, repo, "mod-b", "finding on marked record", recMarked)

	// exclude-search reaches the linked record's response body → drops mod-b.
	fqb := NewFindingsQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, ExcludeTerms: []string{"DROPTOKEN"}})
	found, err := fqb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(found) != 1 || found[0].ModuleID != "mod-a" {
		t.Fatalf("exclude linked-record body: got %d (%v), want only mod-a", len(found), found)
	}

	// exclude-body uses NOT EXISTS over linked records → same result.
	fqb = NewFindingsQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, ExcludeBodySearch: "DROPTOKEN"})
	found, err = fqb.Execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(found) != 1 || found[0].ModuleID != "mod-a" {
		t.Fatalf("exclude-body linked record: got %d (%v), want only mod-a", len(found), found)
	}
}
