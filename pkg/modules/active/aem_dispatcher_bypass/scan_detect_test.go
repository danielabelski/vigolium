package aem_dispatcher_bypass

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
const crxListJSON = `{"total":1,"results":1,"buildCount":1,"downloadName":"pkg.zip","acHandling":"overwrite"}`

// TestDispatcherBypassConfirmsDifferential: clean path blocked (403), bypass
// variant serves the CRX package listing → Critical finding.
func TestDispatcherBypassConfirmsDifferential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/libs/granite/core/content/login.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
		case r.URL.Path == "/crx/packmgr/list.jsp":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html>Forbidden</html>"))
		case strings.HasPrefix(r.URL.Path, "/crx/packmgr/list.jsp"):
			// The mangled bypass variant slips past — dispatcher serves it as CSS.
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte(crxListJSON))
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
		if strings.Contains(res.Info.Name, "CRX Package Manager Listing") {
			s := res.Info.Severity
			sev = &s
		}
	}
	if sev == nil {
		t.Fatalf("expected CRX dispatcher-bypass finding, got %+v", results)
	}
	if *sev != severity.Critical {
		t.Fatalf("expected Critical, got %v", *sev)
	}
}

// TestDispatcherBypassSkipsOpenEndpoint: when the DIRECT path already serves the
// content, it is an open endpoint (sensitive_servlet's job), not a bypass.
func TestDispatcherBypassSkipsOpenEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/libs/granite/core/content/login.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
		case strings.HasPrefix(r.URL.Path, "/crx/packmgr/list.jsp"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(crxListJSON))
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
	for _, res := range results {
		if strings.Contains(res.Info.Name, "Dispatcher") {
			t.Fatalf("open endpoint must not be reported as a bypass: %+v", res)
		}
	}
}

func TestDispatcherBypassSkipsNonAEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/crx/packmgr/list.jsp" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/crx/packmgr/list.jsp") {
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte(crxListJSON))
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
