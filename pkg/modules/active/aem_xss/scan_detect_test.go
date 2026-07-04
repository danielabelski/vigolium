package aem_xss

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const aemLoginBody = `<html><head><title>AEM Sign In</title></head><body>Adobe Experience Manager</body></html>`

// mergeMetadataServer reflects the `path` query param into an HTML body. encode
// controls whether the reflection is HTML-escaped (safe) or raw (vulnerable).
func mergeMetadataServer(t *testing.T, encode bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if r.URL.Path == "/libs/dam/merge/metadata.html" {
			p := r.URL.Query().Get("path")
			if encode {
				p = html.EscapeString(p)
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html>{"assetPaths":["` + p + `"]}</html>`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func markerFromURL(u string) string {
	const a = "alert('"
	i := strings.Index(u, a)
	if i < 0 {
		return ""
	}
	rest := u[i+len(a):]
	j := strings.Index(rest, "'")
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func TestAEMXSSHeadlessConfirmedHigh(t *testing.T) {
	srv := mergeMetadataServer(t, false)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	m := New()
	// Fake browser: report a dialog carrying the URL's marker → confirmed execution.
	m.Probe = func(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		mk := markerFromURL(cfg.URL)
		return &spitolas.ProbeResult{Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: mk}}}, nil
	}

	results, err := m.ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var sev *severity.Severity
	for _, res := range results {
		if strings.Contains(res.Info.Name, "MergeMetadata") {
			s := res.Info.Severity
			sev = &s
		}
	}
	if sev == nil {
		t.Fatalf("expected MergeMetadata XSS finding, got %+v", results)
	}
	if *sev != severity.High {
		t.Fatalf("expected High (browser-confirmed), got %v", *sev)
	}
}

func TestAEMXSSReflectionOnlyLow(t *testing.T) {
	srv := mergeMetadataServer(t, false)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	m := New()
	// Fake browser fires no dialog → reflection-only, low confidence.
	m.Probe = func(_ context.Context, _ spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return &spitolas.ProbeResult{}, nil
	}

	results, err := m.ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	found := false
	for _, res := range results {
		if strings.Contains(res.Info.Name, "MergeMetadata") {
			found = true
			if res.Info.Severity != severity.Low {
				t.Fatalf("reflection-only should be Low, got %v", res.Info.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected reflection-only finding, got %+v", results)
	}
}

func TestAEMXSSEncodedOutputNoFire(t *testing.T) {
	srv := mergeMetadataServer(t, true) // HTML-escapes the reflection
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	m := New()
	m.Probe = func(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return &spitolas.ProbeResult{Dialogs: []spitolas.DialogEvent{{Message: markerFromURL(cfg.URL)}}}, nil
	}

	results, err := m.ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("encoded reflection must not fire, got %+v", results)
	}
}

func TestAEMXSSSkipsNonAEM(t *testing.T) {
	// No login page → ConfirmAEM fails → no probing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/dam/merge/metadata.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html>` + r.URL.Query().Get("path") + `</html>`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	m := New()
	m.Probe = func(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return &spitolas.ProbeResult{Dialogs: []spitolas.DialogEvent{{Message: markerFromURL(cfg.URL)}}}, nil
	}
	results, err := m.ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("non-AEM target must yield no findings, got %+v", results)
	}
}
