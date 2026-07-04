package aem_cloudsettings_injection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const aemLoginBody = `<html><head><title>AEM Sign In</title></head><body>Adobe Experience Manager</body></html>`

// cloudsettingsServer simulates the BulkImportConfigServlet write + ConfDeliveryServlet
// read-back. If evalEL is true it evaluates the EL probe #{7*7} to 49 server-side
// (the vulnerable behavior); otherwise it reflects values verbatim.
func cloudsettingsServer(t *testing.T, evalEL bool) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	props := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == writeBase {
			_ = r.ParseForm()
			mu.Lock()
			for _, k := range []string{"vigmark", "action", "redirectTarget"} {
				if v := r.FormValue(k); v != "" {
					if evalEL {
						v = strings.ReplaceAll(v, "#{7*7}", "49")
					}
					props[k] = v
				}
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == readBase {
			mu.Lock()
			var b strings.Builder
			b.WriteString(`<html><body class="cq-redirect-notice">`)
			for k, v := range props {
				fmt.Fprintf(&b, `<div data-%s="%s"></div>`, k, v)
			}
			b.WriteString(`</body></html>`)
			mu.Unlock()
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(b.String()))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func names(results []*output.ResultEvent) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		out = append(out, r.Info.Name)
	}
	return out
}

func TestPreAuthWriteAndELInjection(t *testing.T) {
	srv := cloudsettingsServer(t, true)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var write, el bool
	for _, res := range results {
		if strings.Contains(res.Info.Name, "Pre-Auth JCR Node Write") {
			write = true
			if res.Info.Severity != severity.Critical {
				t.Errorf("pre-auth write should be Critical, got %v", res.Info.Severity)
			}
		}
		if strings.Contains(res.Info.Name, "Expression Language Injection") {
			el = true
			if res.Info.Severity != severity.Critical {
				t.Errorf("EL injection should be Critical, got %v", res.Info.Severity)
			}
		}
	}
	if !write {
		t.Errorf("expected pre-auth write finding, got %+v", names(results))
	}
	if !el {
		t.Errorf("expected EL injection finding, got %+v", names(results))
	}
}

func TestWriteButNoELWhenLiteralReflection(t *testing.T) {
	// Server reflects values verbatim (no EL evaluation): the write primitive is
	// confirmed, but the EL probe reads back as the literal #{7*7}, so no EL finding.
	srv := cloudsettingsServer(t, false)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var write, el bool
	for _, res := range results {
		if strings.Contains(res.Info.Name, "Pre-Auth JCR Node Write") {
			write = true
		}
		if strings.Contains(res.Info.Name, "Expression Language Injection") {
			el = true
		}
	}
	if !write {
		t.Errorf("expected pre-auth write finding, got %+v", names(results))
	}
	if el {
		t.Errorf("EL injection must not fire on literal reflection, got %+v", names(results))
	}
}

func TestNoWritePrimitiveNoFinding(t *testing.T) {
	// Read-back never reflects the written marker → no exploitable chain.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if r.URL.Path == readBase {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>static content, nothing written</body></html>`))
			return
		}
		if r.Method == http.MethodPost {
			w.WriteHeader(200)
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
		t.Fatalf("no write-back → expected no findings, got %+v", names(results))
	}
}

func TestCloudsettingsSkipsNonAEM(t *testing.T) {
	// No AEM login page / markers → ConfirmAEM fails → no probing.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(plain.Close)
	client := modtest.Requester(t)
	rr := modtest.Request(t, plain.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("non-AEM target must yield no findings, got %+v", names(results))
	}
}
