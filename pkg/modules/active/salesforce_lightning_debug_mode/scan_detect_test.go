package salesforce_lightning_debug_mode

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// lightningServer emulates a Lightning host: a live Aura gateway (invalidSession
// on the empty probe) plus a landing page whose Aura bootstrap declares `mode`.
func lightningServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	landing := `<html><head><script>window.Aura={};auraConfig={"context":{"mode":"` + mode +
		`","fwuid":"abc","app":"siteforce:communityApp"}};</script></head><body>siteforce:communityApp</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/aura"):
			// The gateway probe posts a bare "{}" body (no message= field).
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"event":{"descriptor":"markup://aura:invalidSession"}}`))
		case r.URL.Path == "/s/" || r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(landing))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDebugModeFiresOnProddebug(t *testing.T) {
	srv := lightningServer(t, "PRODDEBUG")
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 debug-mode finding, got %d: %+v", len(results), results)
	}
	if results[0].Info.Severity != severity.Medium {
		t.Fatalf("expected Medium severity, got %v", results[0].Info.Severity)
	}
	if results[0].Metadata["aura_mode"] != "PRODDEBUG" {
		t.Fatalf("expected aura_mode PRODDEBUG, got %v", results[0].Metadata["aura_mode"])
	}
}

func TestDebugModeNoFireOnProd(t *testing.T) {
	// Production mode is the safe case and must never fire.
	srv := lightningServer(t, "PROD")
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("PROD mode must not fire, got %+v", results)
	}
}

func TestDebugModeSkipsNonSalesforce(t *testing.T) {
	// No Aura gateway → not a Lightning host → no probing.
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
