package aem_oob_injection

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const aemLoginBody = `<html><head><title>AEM Sign In</title></head><body>Adobe Experience Manager</body></html>`

// fakeOAST is a minimal OASTProvider that hands out a fixed collaborator host and
// records the payloads planted at it.
type fakeOAST struct {
	host     string
	enabled  bool
	mu       sync.Mutex
	payloads []string
}

func (f *fakeOAST) GenerateURL(_, _, _, _, _ string) string { return f.host }
func (f *fakeOAST) RecordPayload(_, payload string) {
	f.mu.Lock()
	f.payloads = append(f.payloads, payload)
	f.mu.Unlock()
}
func (f *fakeOAST) Enabled() bool { return f.enabled }

func TestFiresBothBlindPayloads(t *testing.T) {
	const oastHost = "abc123.oast.example"

	var mu sync.Mutex
	var gotAuthURL string
	var packmgrHit bool
	var packmgrBodyHasHost bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/libs/granite/core/content/login.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
		// A real AEM servlet answers a wrong-method GET with 405 — the reachability
		// pre-check that gates the blind payloads keys on this.
		case r.Method == http.MethodGet && (r.URL.Path == "/services/accesstoken/verify" || r.URL.Path == "/crx/packmgr/service/exec.json"):
			w.WriteHeader(http.StatusMethodNotAllowed)
		case r.Method == http.MethodPost && r.URL.Path == "/services/accesstoken/verify":
			_ = r.ParseForm()
			mu.Lock()
			gotAuthURL = r.FormValue("auth_url")
			mu.Unlock()
			w.WriteHeader(200)
		case r.Method == http.MethodPost && r.URL.Path == "/crx/packmgr/service/exec.json":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			packmgrHit = true
			packmgrBodyHasHost = strings.Contains(string(body), oastHost)
			mu.Unlock()
			w.WriteHeader(200)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	oast := &fakeOAST{host: oastHost, enabled: true}
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	_, err := New().ScanPerHost(rr, client, &modkit.ScanContext{OASTProvider: oast})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(gotAuthURL, oastHost) {
		t.Errorf("accesstoken auth_url should carry the collaborator host, got %q", gotAuthURL)
	}
	if !packmgrHit {
		t.Errorf("expected a package-manager upload POST")
	}
	if !packmgrBodyHasHost {
		t.Errorf("packmgr upload body should embed the collaborator host in privileges.xml")
	}
	oast.mu.Lock()
	nPayloads := len(oast.payloads)
	oast.mu.Unlock()
	if nPayloads < 2 {
		t.Errorf("expected both payloads recorded with the OAST service, got %d", nPayloads)
	}
}

func TestNoFireWhenEndpointsAbsent(t *testing.T) {
	// Host is confirmed AEM (login page present) but neither vulnerable servlet
	// exists (GET → 404). The reachability pre-check must suppress the blind payloads.
	var posted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if r.Method == http.MethodPost {
			posted = true
		}
		http.NotFound(w, r) // servlets absent
	}))
	t.Cleanup(srv.Close)

	oast := &fakeOAST{host: "abc123.oast.example", enabled: true}
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	_, err := New().ScanPerHost(rr, client, &modkit.ScanContext{OASTProvider: oast})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if posted {
		t.Errorf("must not fire blind payloads when the target servlets are absent")
	}
}

func TestNoOASTNoFire(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if r.Method == http.MethodPost {
			hit = true
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	// No OASTProvider → blind module must not fire any payloads.
	_, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if hit {
		t.Errorf("module must not send payloads without OAST configured")
	}
}
