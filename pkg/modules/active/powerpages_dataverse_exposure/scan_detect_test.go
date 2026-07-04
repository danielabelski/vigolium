package powerpages_dataverse_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// dataverseNotFound is the Dataverse OData error body for an unknown entity set.
const dataverseNotFound = `{"error":{"code":"","message":"Resource not found for the segment 'x'.","innererror":{"code":"9004010C","message":"Resource not found for the segment 'x'."}}}`

func contactsBody() string {
	return `{"@odata.context":"https://x/_api/$metadata#contacts","@odata.count":42,"value":[` +
		`{"contactid":"00000000-0000-0000-0000-000000000001","fullname":"Jane Doe","emailaddress1":"jane@example.com","telephone1":"555-0100"}` +
		`]}`
}

// serveDataverse serves a Dataverse-like /_api/ router: `tables` maps an entity
// set to its 200 body; the bogus probe set and any unknown table return a
// Dataverse 404.
func serveDataverse(t *testing.T, tables map[string]string, status map[string]int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/_api/") {
			http.NotFound(w, r)
			return
		}
		set := strings.TrimPrefix(r.URL.Path, "/_api/")
		if body, ok := tables[set]; ok {
			code := 200
			if s, ok := status[set]; ok {
				code = s
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
			return
		}
		// Unknown / bogus entity set → Dataverse 404.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(dataverseNotFound))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestContactsExposureCritical(t *testing.T) {
	srv := serveDataverse(t, map[string]string{
		"contacts": contactsBody(),
	}, nil)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var got *severity.Severity
	for _, res := range results {
		if strings.Contains(res.Info.Name, "contacts") && !strings.Contains(res.Info.Name, "column-restricted") {
			s := res.Info.Severity
			got = &s
		}
	}
	if got == nil {
		t.Fatalf("expected contacts exposure finding, got %+v", results)
	}
	if *got != severity.Critical {
		t.Fatalf("expected Critical severity for contacts, got %v", *got)
	}
}

func TestColumnRestrictedMedium(t *testing.T) {
	// accounts is Web-API-enabled and reachable but returns 403/90040101.
	forbidden := `{"error":{"code":"","message":"Attribute x in table account is not enabled for Web Api.","innererror":{"code":"90040101"}}}`
	srv := serveDataverse(t, map[string]string{
		"accounts": forbidden,
	}, map[string]int{"accounts": 403})
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	found := false
	for _, res := range results {
		if strings.Contains(res.Info.Name, "accounts") && strings.Contains(res.Info.Name, "column-restricted") {
			found = true
			if res.Info.Severity != severity.Medium {
				t.Fatalf("expected Medium (capped) severity for column-restricted, got %v", res.Info.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected column-restricted finding for accounts, got %+v", results)
	}
}

func TestSkipsNonPowerPages(t *testing.T) {
	// /_api/* returns plain HTML 404 (no Dataverse error) → not a portal.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = w.Write([]byte("<html><body>Not Found</body></html>"))
	}))
	t.Cleanup(srv.Close)

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("non-Power-Pages target must yield no findings, got %+v", results)
	}
}

func TestCatchAllApiRejected(t *testing.T) {
	// A site that 200s EVERY /_api/ path (including the bogus probe set) with a
	// value array must not produce findings — the API doesn't discriminate.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(contactsBody()))
	}))
	t.Cleanup(srv.Close)

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("catch-all /_api must yield no findings, got %+v", results)
	}
}
