package aem_console_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// aemLoginBody makes ConfirmAEM's active gate pass (Granite login → "AEM Sign In").
const aemLoginBody = `<html><head><title>AEM Sign In</title></head><body>Adobe Experience Manager</body></html>`

func newAEMServer(t *testing.T, extra map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if body, ok := extra[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConsoleExposureDetectsCRXDE(t *testing.T) {
	srv := newAEMServer(t, map[string]string{
		"/crx/de/index.jsp": `<html><head><title>CRXDE Lite</title></head><body>crxde</body></html>`,
	})
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected CRXDE Lite finding, got none")
	}
	found := false
	for _, res := range results {
		if strings.Contains(res.Info.Name, "CRXDE Lite") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CRXDE Lite finding, got %+v", results)
	}
}

func TestConsoleExposureRequiresMarkerCombo(t *testing.T) {
	// Content Explorer needs BOTH "Content Explorer" AND crx.default/Workspace.
	// Serving only the first must NOT fire (guards against a generic echo).
	srv := newAEMServer(t, map[string]string{
		"/crx/explorer/browser/index.jsp": `<html><body>Content Explorer only</body></html>`,
	})
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	for _, res := range results {
		if strings.Contains(res.Info.Name, "Content Explorer") {
			t.Fatalf("should not fire on partial marker match: %+v", res)
		}
	}
}

// TestConsoleExposureSkipsWAFChallenge: a 200 response carrying the CRXDE title
// but flagged as a WAF/CDN challenge (Cf-Mitigated) must not fire — status==200
// alone would pass, so this exercises the Blocked gate.
func TestConsoleExposureSkipsWAFChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if r.URL.Path == "/crx/de/index.jsp" {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Cf-Mitigated", "challenge") // edge challenge, 200 status
			_, _ = w.Write([]byte(`<html><head><title>CRXDE Lite</title></head></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	for _, res := range results {
		if strings.Contains(res.Info.Name, "CRXDE Lite") {
			t.Fatalf("WAF 200-challenge must not fire: %+v", res)
		}
	}
}

func TestConsoleExposureSkipsNonAEM(t *testing.T) {
	// No AEM login page served → ConfirmAEM fails → module must not probe/emit,
	// even though the CRXDE title is present.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crx/de/index.jsp" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<title>CRXDE Lite</title>`))
			return
		}
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
		t.Fatalf("non-AEM target must yield no findings, got %+v", results)
	}
}
