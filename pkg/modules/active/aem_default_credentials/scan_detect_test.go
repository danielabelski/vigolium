package aem_default_credentials

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const aemLoginBody = `<html><head><title>AEM Sign In</title></head><body>Adobe Experience Manager</body></html>`

func TestGraniteDefaultAdminAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/libs/granite/core/content/login.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
		case granitePath:
			_ = r.ParseForm()
			if r.Form.Get("j_username") == "admin" && r.Form.Get("j_password") == "admin" {
				w.Header().Set("Set-Cookie", "login-token=abc123; Path=/; HttpOnly")
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"ok":true} login-token=abc123`))
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`invalid_login`))
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
		if strings.Contains(res.Info.Name, "admin:admin") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected admin:admin default-credential finding, got %+v", results)
	}
}

// TestGraniteAlwaysYesOracleNoFire: an endpoint that issues a login-token for ANY
// credential (including the random negative control) must not produce a finding.
func TestGraniteAlwaysYesOracleNoFire(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/libs/granite/core/content/login.html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
		case granitePath:
			w.Header().Set("Set-Cookie", "login-token=always; Path=/")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`login-token=always`))
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
	if len(results) != 0 {
		t.Fatalf("always-yes oracle must not fire (negative control): %+v", results)
	}
}

func TestDefaultCredsSkipsNonAEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == granitePath {
			_ = r.ParseForm()
			if r.Form.Get("j_username") == "admin" {
				w.Header().Set("Set-Cookie", "login-token=abc")
				_, _ = w.Write([]byte("login-token=abc"))
				return
			}
			_, _ = w.Write([]byte("invalid_login"))
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
