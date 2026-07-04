package aem_rce

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
const groovyBody = `<html><head><title>Groovy Console</title></head><body>Groovy Web Console - Run Script (groovy.lang)</body></html>`

func TestGroovyConsoleExposedCritical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/libs/granite/core/content/login.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
		case "/etc/groovyconsole.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(groovyBody))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	var sev *severity.Severity
	for _, res := range results {
		if strings.Contains(res.Info.Name, "Groovy Console") {
			s := res.Info.Severity
			sev = &s
		}
	}
	if sev == nil {
		t.Fatalf("expected Groovy Console finding, got %+v", results)
	}
	if *sev != severity.Critical {
		t.Fatalf("expected Critical, got %v", *sev)
	}
}

func TestRCESkipsNonAEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/etc/groovyconsole.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(groovyBody))
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
