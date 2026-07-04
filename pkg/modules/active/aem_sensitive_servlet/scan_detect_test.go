package aem_sensitive_servlet

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const aemLoginBody = `<html><head><title>AEM Sign In</title></head><body>Adobe Experience Manager</body></html>`

// route serves a fixed JSON/text body for an exact path, plus the AEM login page
// so ConfirmAEM passes.
func serve(t *testing.T, routes map[string]route) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if rt, ok := routes[r.URL.Path]; ok {
			w.Header().Set("Content-Type", rt.ct)
			_, _ = w.Write([]byte(rt.body))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type route struct {
	ct   string
	body string
}

func TestQueryBuilderPasswordHashCritical(t *testing.T) {
	qbBody := `{"success":true,"total":1,"hits":[{"jcr:primaryType":"rep:User","rep:authorizableId":"admin","rep:password":"{SHA-256}deadbeef"}]}`
	srv := serve(t, map[string]route{
		"/bin/querybuilder.json": {ct: "application/json", body: qbBody},
	})
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var got *severity.Severity
	for _, res := range results {
		if strings.Contains(res.Info.Name, "Password Hash Disclosure") {
			s := res.Info.Severity
			got = &s
		}
	}
	if got == nil {
		t.Fatalf("expected QueryBuilder password-hash finding, got %+v", results)
	}
	if *got != severity.Critical {
		t.Fatalf("expected Critical severity, got %v", *got)
	}
}

func TestDefaultGetServletJSONDump(t *testing.T) {
	dump := `{"jcr:primaryType":"cq:Page","jcr:createdBy":"admin","jcr:created":"2020"}`
	srv := serve(t, map[string]route{
		"/etc.tidy.infinity.json": {ct: "application/json", body: dump},
	})
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	found := false
	for _, res := range results {
		if strings.Contains(res.Info.Name, "DefaultGetServlet") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected DefaultGetServlet dump finding, got %+v", results)
	}
}

func TestUserInfoPartialMarkerNoFire(t *testing.T) {
	// Only "userID" without "userName" must not fire.
	srv := serve(t, map[string]route{
		"/libs/cq/security/userinfo.json": {ct: "application/json", body: `{"userID":"anonymous"}`},
	})
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	for _, res := range results {
		if strings.Contains(res.Info.Name, "UserInfo") {
			t.Fatalf("partial marker should not fire: %+v", res)
		}
	}
}

func TestSensitiveServletSkipsNonAEM(t *testing.T) {
	// No AEM login page → ConfirmAEM fails → no probing even though the servlet
	// body would match.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bin/querybuilder.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"hits":[{"rep:password":"x"}]}`))
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
