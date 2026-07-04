package aem_content_discovery

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// names lists the finding names for a readable test failure message.
func names(results []*output.ResultEvent) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		out = append(out, r.Info.Name)
	}
	return out
}

const aemLoginBody = `<html><head><title>AEM Sign In</title></head><body>Adobe Experience Manager</body></html>`

// serveTree serves a fixed JCR tree keyed by exact request path, plus the Granite
// login page so ConfirmAEM passes.
func serveTree(t *testing.T, tree map[string]string, qb http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if r.URL.Path == "/bin/querybuilder.json" && qb != nil {
			qb(w, r)
			return
		}
		if body, ok := tree[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTreeWalkEnumeratesHarvestsSecretAndUsers(t *testing.T) {
	tree := map[string]string{
		"/libs.1.json":    `{"jcr:primaryType":"nt:folder","granite":{"jcr:primaryType":"nt:folder"}}`,
		"/.1.json":        `{"jcr:primaryType":"rep:root","content":{"jcr:primaryType":"sling:Folder"},"apps":{"jcr:primaryType":"sling:Folder"},"home":{"jcr:primaryType":"rep:AuthorizableFolder"}}`,
		"/content.1.json": `{"jcr:primaryType":"sling:Folder","dam":{"jcr:primaryType":"sling:Folder"},"mysite":{"jcr:primaryType":"cq:Page"}}`,
		"/content/dam.1.json":    `{"jcr:primaryType":"sling:Folder"}`,
		"/content/mysite.1.json": `{"jcr:primaryType":"cq:Page"}`,
		"/apps.1.json":           `{"jcr:primaryType":"sling:Folder","system":{"jcr:primaryType":"sling:Folder"}}`,
		"/apps/system.1.json":    `{"jcr:primaryType":"sling:Folder","oracledbdetails":{"jcr:primaryType":"sling:OsgiConfig","password":"w3lcome123","jdbcconnectionuri":"jdbc:oracle:thin:@//db.internal:1524/PROD"}}`,
		"/home.1.json":           `{"jcr:primaryType":"rep:AuthorizableFolder","users":{"jcr:primaryType":"rep:AuthorizableFolder"}}`,
		"/home/users.1.json":     `{"jcr:primaryType":"rep:AuthorizableFolder","admin":{"jcr:primaryType":"rep:User","rep:authorizableId":"admin","rep:principalName":"admin"}}`,
	}
	srv := serveTree(t, tree, nil)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	var haveTree, haveSecret, haveUsers bool
	var secretSev severity.Severity
	for _, res := range results {
		switch {
		case strings.Contains(res.Info.Name, "Repository Tree Enumeration"):
			haveTree = true
		case strings.Contains(res.Info.Name, "Configuration Secret"):
			haveSecret = true
			secretSev = res.Info.Severity
		case strings.Contains(res.Info.Name, "User Account Enumeration"):
			haveUsers = true
		}
	}
	if !haveTree {
		t.Errorf("expected tree-enumeration finding, got %+v", names(results))
	}
	if !haveSecret {
		t.Errorf("expected config-secret finding, got %+v", names(results))
	} else if secretSev != severity.Critical {
		t.Errorf("config secret should be Critical, got %v", secretSev)
	}
	if !haveUsers {
		t.Errorf("expected user-enumeration finding, got %+v", names(results))
	}
}

func TestQueryBuilderWritableAndPackages(t *testing.T) {
	qb := func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "hasPermission=jcr:write") ||
			strings.Contains(q, "hasPermission=jcr:addChildNodes") ||
			strings.Contains(q, "hasPermission=jcr:modifyProperties"):
			_, _ = w.Write([]byte(`{"success":true,"results":1,"total":1,"hits":[{"jcr:path":"/content/usergenerated/etc/commerce/smartlists"}]}`))
		case strings.Contains(q, "hasPermission=jcr:"): // bogus-permission negative control
			_, _ = w.Write([]byte(`{"success":true,"results":0,"total":0,"hits":[]}`))
		case strings.Contains(q, "nodename=*.zip"):
			_, _ = w.Write([]byte(`{"success":true,"results":1,"total":1,"hits":[{"jcr:path":"/etc/packages/my_app/backup-1.0.zip/jcr:content"}]}`))
		case strings.Contains(q, "nodename=*."): // impossible-nodename negative control
			_, _ = w.Write([]byte(`{"success":true,"results":0,"total":0,"hits":[]}`))
		default: // discovery probe
			_, _ = w.Write([]byte(`{"success":true,"results":1,"total":1,"hits":[{"jcr:path":"/"}]}`))
		}
	}
	srv := serveTree(t, map[string]string{}, qb)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var haveWritable, havePackages bool
	for _, res := range results {
		if strings.Contains(res.Info.Name, "Anonymous Writable JCR Node") {
			haveWritable = true
			if res.Info.Severity != severity.High {
				t.Errorf("writable node should be High, got %v", res.Info.Severity)
			}
		}
		if strings.Contains(res.Info.Name, "Deployment Package") {
			havePackages = true
		}
	}
	if !haveWritable {
		t.Errorf("expected writable-node finding, got %+v", names(results))
	}
	if !havePackages {
		t.Errorf("expected package-disclosure finding, got %+v", names(results))
	}
}

func TestQueryBuilderCatchAllNoWritableFinding(t *testing.T) {
	// A catch-all QueryBuilder that returns total>0 for ANY query, including the
	// bogus-permission negative control, must not yield a writable-node finding.
	qb := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"results":1,"total":1,"hits":[{"jcr:path":"/x"}]}`))
	}
	srv := serveTree(t, map[string]string{}, qb)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	for _, res := range results {
		if strings.Contains(res.Info.Name, "Anonymous Writable JCR Node") {
			t.Fatalf("catch-all QueryBuilder must not fire writable-node finding: %+v", res)
		}
	}
}

func TestContentDiscoverySkipsNonAEM(t *testing.T) {
	// No login page and no AEM markers → ConfirmAEM fails → no probing at all, even
	// though a querybuilder-like body is served.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"total":1,"hits":[{"jcr:path":"/"}]}`))
	}))
	t.Cleanup(srv.Close)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("non-AEM target must yield no findings, got %+v", names(results))
	}
}
