package aem_ssrf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const aemLoginBody = `<html><head><title>AEM Sign In</title></head><body>Adobe Experience Manager</body></html>`

// TestSSRFServletSpecificMount: the servlet responds (400) while a random sibling
// 404s → confirmed as a specific mount (Medium/Tentative).
func TestSSRFServletSpecificMount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/libs/granite/core/content/login.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
		case "/libs/opensocial/proxy":
			w.WriteHeader(400)
			_, _ = w.Write([]byte("missing url parameter"))
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
	found := false
	for _, res := range results {
		if strings.Contains(res.Info.Name, "OpenSocial") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected OpenSocial SSRF-servlet exposure, got %+v", results)
	}
}

// TestSSRFCatchAllNoFire: a directory that answers EVERY child (including the
// random sibling) is a catch-all, not a specific servlet mount.
func TestSSRFCatchAllNoFire(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/libs/opensocial/") {
			w.WriteHeader(400) // answers any child → catch-all
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
		if strings.Contains(res.Info.Name, "OpenSocial") {
			t.Fatalf("catch-all directory must not fire: %+v", res)
		}
	}
}

func TestSSRFSkipsNonAEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/opensocial/proxy" {
			w.WriteHeader(400)
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
