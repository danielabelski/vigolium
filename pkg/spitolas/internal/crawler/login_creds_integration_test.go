//go:build integration

package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// loginCredOutcome is the subset of crawl stats the login-cred tests assert on.
type loginCredOutcome struct {
	tried     int
	succeeded int
	url       string
	rec       *recordingWriter
}

// runLoginCredCrawl runs the crawler against mux with the common-credential login
// pass enabled (and the login-CTA priming off, so the pass — not the CTA driver —
// is what exercises the login form).
func runLoginCredCrawl(t *testing.T, mux *http.ServeMux) loginCredOutcome {
	t.Helper()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 0
	cfg.MaxDepth = 2
	cfg.MaxDuration = 60 * time.Second
	cfg.SPASettleTimeout = 2 * time.Second
	cfg.LoginCTAPriming = false        // isolate the credential pass
	cfg.LoginCredentialAttempts = true // the feature under test

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New crawler: %v", err)
	}
	rec := &recordingWriter{}
	c.SetWriter(rec)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := c.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return loginCredOutcome{
		tried:     result.Stats.LoginCredsTried,
		succeeded: result.Stats.LoginCredsSucceeded,
		url:       result.Stats.LoginCredsURL,
		rec:       rec,
	}
}

// defaultCredLoginMux serves a local username/password login form that accepts
// admin:admin, sets a session cookie, and redirects to an authenticated
// dashboard carrying a Logout affordance. Any other credential re-serves the
// login form (password field still present → not authenticated).
func defaultCredLoginMux() *http.ServeMux {
	const loginPage = `<!doctype html><html><body>
		<h1>Please sign in</h1>
		<form action="/login" method="post">
			<input type="text" name="username" placeholder="Username">
			<input type="password" name="password" placeholder="Password">
			<button type="submit">Sign in</button>
		</form>
	</body></html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(loginPage))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("username") == "admin" && r.FormValue("password") == "admin" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/"})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		// Failed login: re-serve the login form (still a login page).
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(loginPage))
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie("sid"); err != nil || ck.Value != "ok" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body>
			<h1>Welcome, admin</h1>
			<a href="/logout">Logout</a>
			<a href="/settings">Settings</a>
		</body></html>`))
	})
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie("sid"); err != nil || ck.Value != "ok" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body><h1>Settings</h1></body></html>`))
	})
	return mux
}

// TestLoginCredsAuthenticatesWithDefaultCreds verifies the pass confirms the
// login form, sprays common credentials, authenticates with admin:admin, and
// records the success — and that the authenticated area is reached (the session
// cookie persists, so /dashboard and /settings are captured).
func TestLoginCredsAuthenticatesWithDefaultCreds(t *testing.T) {
	out := runLoginCredCrawl(t, defaultCredLoginMux())

	if out.succeeded != 1 {
		t.Fatalf("LoginCredsSucceeded = %d, want 1", out.succeeded)
	}
	if out.tried < 1 {
		t.Errorf("LoginCredsTried = %d, want >= 1", out.tried)
	}
	if out.url == "" {
		t.Errorf("LoginCredsURL should record the login form URL")
	}
	// The successful login is captured, and the now-authenticated area is reached.
	if !out.rec.sawContaining("/login") {
		t.Errorf("expected the /login submission to be captured")
	}
	if !out.rec.sawContaining("/dashboard") {
		t.Errorf("expected the authenticated /dashboard to be reached and captured")
	}
}

// noDefaultCredLoginMux serves a login form that never accepts any of the tried
// credentials — the pass must NOT report success (and its negative control must
// not be fooled).
func noDefaultCredLoginMux() *http.ServeMux {
	const loginPage = `<!doctype html><html><body>
		<h1>Please sign in</h1>
		<form action="/login" method="post">
			<input type="text" name="username" placeholder="Username">
			<input type="password" name="password" placeholder="Password">
			<button type="submit">Sign in</button>
		</form>
	</body></html>`

	mux := http.NewServeMux()
	serve := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(loginPage))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		serve(w)
	})
	// Every login attempt fails: always re-serve the login form.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { serve(w) })
	return mux
}

// TestLoginCredsNoDefaultCredsNoSuccess verifies that a form which rejects every
// tried credential yields no reported success.
func TestLoginCredsNoDefaultCredsNoSuccess(t *testing.T) {
	out := runLoginCredCrawl(t, noDefaultCredLoginMux())
	if out.succeeded != 0 {
		t.Fatalf("LoginCredsSucceeded = %d, want 0 (no credential should authenticate)", out.succeeded)
	}
}

// TestLoginCredsDisabledByDefault verifies the pass does not run when the config
// gate is off, even on a login form that would accept admin:admin.
func TestLoginCredsDisabledByDefault(t *testing.T) {
	server := httptest.NewServer(defaultCredLoginMux())
	t.Cleanup(server.Close)

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	cfg.MaxDepth = 1
	cfg.MaxDuration = 30 * time.Second
	cfg.SPASettleTimeout = 2 * time.Second
	cfg.LoginCTAPriming = false
	// LoginCredentialAttempts left at its default (false).

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New crawler: %v", err)
	}
	c.SetWriter(&recordingWriter{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := c.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Stats.LoginCredsTried != 0 || result.Stats.LoginCredsSucceeded != 0 {
		t.Errorf("login-cred pass ran while disabled: tried=%d succeeded=%d",
			result.Stats.LoginCredsTried, result.Stats.LoginCredsSucceeded)
	}
}
