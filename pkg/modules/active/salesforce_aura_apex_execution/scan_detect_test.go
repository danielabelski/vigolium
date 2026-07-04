package salesforce_aura_apex_execution

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const contextHTML = `<html><head><script src="/s/sfsites/l/ABC123ctx~tok/app.js"></script></head><body>siteforce:communityApp</body></html>`

// apexServer emulates the Aura gateway. The apex closure decides the response for
// an ApexActionController.execute message so each test can control whether the
// benign probe and/or the bogus controls "succeed".
func apexServer(t *testing.T, apex func(msg string) string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/s/" || r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(contextHTML))
		case strings.HasSuffix(r.URL.Path, "/aura"):
			msg := r.FormValue("message")
			if msg == "" || msg == "{}" {
				_, _ = w.Write([]byte(`{"event":{"descriptor":"markup://aura:invalidSession"}}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(apex(msg)))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const (
	apexSuccess = `{"actions":[{"id":"209;a","state":"SUCCESS","returnValue":[]}]}`
	apexError   = `{"actions":[{"id":"209;a","state":"ERROR","error":[{"message":"System.StringException: no access"}]}]}`
)

func TestApexExecutionFiresWhenGuestCanRunApex(t *testing.T) {
	// Benign Wave.Templates.getTemplates succeeds; any bogus class/method errors.
	srv := apexServer(t, func(msg string) string {
		if strings.Contains(msg, "getTemplates") {
			return apexSuccess
		}
		return apexError
	})
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 apex-execution finding, got %d: %+v", len(results), results)
	}
	if results[0].Info.Severity != severity.High {
		t.Fatalf("expected High severity, got %v", results[0].Info.Severity)
	}
}

func TestApexExecutionNoFireWhenApexBlocked(t *testing.T) {
	// Every ApexActionController.execute (benign included) is denied → no finding.
	srv := apexServer(t, func(string) string { return apexError })
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("blocked guest apex must not fire, got %+v", results)
	}
}

func TestApexExecutionSkipsCatchAllEndpoint(t *testing.T) {
	// The endpoint SUCCESS-stamps everything, including the bogus controls → the
	// negative control fails and the host is skipped (no false positive).
	srv := apexServer(t, func(string) string { return apexSuccess })
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("catch-all endpoint must be skipped, got %+v", results)
	}
}

func TestApexExecutionSkipsNonSalesforce(t *testing.T) {
	// No Aura gateway → Prepare fails → no probing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("non-Salesforce target must yield no findings, got %+v", results)
	}
}
