package servicenow_kb_widget_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const snHTML = `<html><head><script>var g_ck = 'TOKENabcdef0123456789ABCDEF';window.NOW={};</script></head><body>GlideForm</body></html>`

// snServer emulates a ServiceNow instance with a KB Article Page widget. exposed
// is the set of KB ids that return content; catchAll makes every id (incl. the
// bogus probe) leak.
func snServer(t *testing.T, exposed map[string]bool, catchAll bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/login.do" || r.URL.Path == "/sp") {
			w.Header().Set("Set-Cookie", "glide_user_route=glide.deadbeef; path=/; HttpOnly")
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(snHTML))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/now/sp/widget/") {
			if r.Header.Get("X-UserToken") == "" {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			id := r.URL.Query().Get("sys_id")
			if catchAll || exposed[id] {
				_, _ = w.Write([]byte(`{"result":{"data":{"kbName":"Corp KB","short_description":"Reset your VPN password","text":"<p>Internal procedure</p>","sys_id":"` + id + `"}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"result":{"data":{"text":"","short_description":""}}}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestKBExposureAggregatesArticles(t *testing.T) {
	srv := snServer(t, map[string]bool{"KB0000001": true, "KB0000002": true, "KB0000003": true}, false)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 aggregate KB finding, got %d: %+v", len(results), results)
	}
	if results[0].Info.Severity != severity.High {
		t.Fatalf("expected High severity, got %v", results[0].Info.Severity)
	}
	if !strings.Contains(results[0].Info.Description, "KB0000001") {
		t.Fatalf("expected exposed KB ids in description, got %q", results[0].Info.Description)
	}
}

func TestKBCatchAllRejected(t *testing.T) {
	srv := snServer(t, nil, true)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("catch-all KB widget must yield no findings, got %+v", results)
	}
}

func TestKBSkipsNonServiceNow(t *testing.T) {
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
		t.Fatalf("non-ServiceNow target must yield no findings, got %+v", results)
	}
}
