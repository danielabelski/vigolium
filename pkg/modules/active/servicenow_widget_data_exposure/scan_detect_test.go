package servicenow_widget_data_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// snHTML is a ServiceNow portal page carrying the g_ck token + a glide cookie.
const snHTML = `<html><head><script>var g_ck = 'TOKENabcdef0123456789ABCDEF';window.NOW={};</script></head><body>GlideForm</body></html>`

// snServer emulates a ServiceNow instance. exposed is the set of tables whose
// Simple List widget returns records; catchAll makes every table (incl. bogus)
// leak; tokenFail makes every widget POST 401.
func snServer(t *testing.T, exposed map[string]bool, catchAll, tokenFail bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/login.do" || r.URL.Path == "/sp") {
			w.Header().Set("Set-Cookie", "glide_user_route=glide.deadbeef; path=/; HttpOnly")
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(snHTML))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/now/sp/widget/") {
			if tokenFail || r.Header.Get("X-UserToken") == "" {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			tbl := r.URL.Query().Get("t")
			if catchAll || exposed[tbl] {
				_, _ = w.Write([]byte(`{"result":{"data":{"isValid":true,"count":3,"list":[{"sys_id":"abc","className":"` + tbl + `","display_field":{"display_value":"Jane Doe"}}]}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"result":{"data":{"isValid":false,"count":0,"list":[]}}}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWidgetExposureSysUserCritical(t *testing.T) {
	srv := snServer(t, map[string]bool{"sys_user": true, "incident": true}, false, false)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var sysUser, incident *severity.Severity
	for _, res := range results {
		switch {
		case strings.HasSuffix(res.Info.Name, "sys_user"):
			s := res.Info.Severity
			sysUser = &s
		case strings.HasSuffix(res.Info.Name, "incident"):
			s := res.Info.Severity
			incident = &s
		}
	}
	if sysUser == nil || *sysUser != severity.Critical {
		t.Fatalf("expected sys_user Critical, got %+v", results)
	}
	if incident == nil || *incident != severity.High {
		t.Fatalf("expected incident High, got %+v", results)
	}
}

func TestWidgetCatchAllRejected(t *testing.T) {
	srv := snServer(t, nil, true, false)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("catch-all widget must yield no findings, got %+v", results)
	}
}

func TestWidgetTokenFailNoFinding(t *testing.T) {
	srv := snServer(t, map[string]bool{"sys_user": true}, false, true)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("401 token failure must yield no findings, got %+v", results)
	}
}

func TestWidgetSkipsNonServiceNow(t *testing.T) {
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
