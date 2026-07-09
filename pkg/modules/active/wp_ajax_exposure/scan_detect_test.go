package wp_ajax_exposure

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// readAction extracts the WordPress "action" form parameter from a POST body.
func readAction(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	vals, _ := url.ParseQuery(string(body))
	return vals.Get("action")
}

// TestScanPerRequest_DetectsExposedAction drives the real scan method against a
// host that behaves like WordPress: admin-ajax.php returns "0" for unregistered
// actions (the control probe) but a distinct payload for a known-vulnerable
// nopriv action, signalling the handler is wired up and unauthenticated.
func TestScanPerRequest_DetectsExposedAction(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Non-existent GET paths 404 so the wildcard probe doesn't flag the
		// host as an SPA shell.
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/wp-admin/admin-ajax.php" {
			action := readAction(r)
			if action == "revslider_show_image" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("admin-ajax: missing image id parameter for revslider handler"))
				return
			}
			// Unregistered/control action → WordPress replies "0".
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("0"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when a vulnerable nopriv AJAX action responds")
}

// TestScanPerRequest_NoFalsePositive ensures a WordPress host that returns "0"
// for every action (no exposed handlers) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/wp-admin/admin-ajax.php" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("0")) // every action unregistered
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a WordPress host with no exposed actions must not yield a finding")
}

// TestScanPerRequest_NoFP_ActionReflectingCatchAll reproduces a catch-all / echo
// host that mirrors the admin-ajax POST back: it answers every action with a
// small body echoing "action=<name>", so a marker that is a substring of the
// action name ("revslider"/"show_image" inside "revslider_show_image") appears in
// the response even though no plugin handler ran. The control probe (a random
// action) is echoed too — small and non-HTML — so it passes the WordPress-shape
// gates, and the per-action head differs from the control so the control-match
// gate does not fire. Only the reflected-action strip, which removes the echoed
// action name before marker matching, suppresses the finding.
func TestScanPerRequest_NoFP_ActionReflectingCatchAll(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("nope"))
			return
		}
		if r.URL.Path == "/wp-admin/admin-ajax.php" {
			w.WriteHeader(http.StatusOK)
			// Mirror the requested action back — a small, non-HTML echo with no
			// plugin-specific token of its own.
			_, _ = w.Write([]byte("received action=" + readAction(r)))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an admin-ajax echo/catch-all mirroring the action name must not forge a plugin finding")
}

// TestScanPerRequest_GenericErrorPageNoFalsePositive reproduces the reported
// false positive: a WordPress-ish host whose admin-ajax.php returns the small
// "0" control body for unregistered actions but answers ai1wm_export with a
// generic "load-failed … Refresh" HTML error page (as help.initech.com did). The
// response differs from the control probe yet carries no All-in-One WP
// Migration marker, so it must NOT be reported as an exposed export handler.
func TestScanPerRequest_GenericErrorPageNoFalsePositive(t *testing.T) {
	t.Parallel()
	// The exact shape of the page that triggered the FP — note it contains
	// </html> (not the opening <html>) and no plugin tokens.
	loadFailed := `<div class="err"><h1>Error</h1><h3 id="load-failed-url"></h3>` +
		`<a onclick="window.location.reload(!0)" href="#" ` +
		`style="color:#00a5cf;text-decoration:none">Refresh</a></div></div></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/wp-admin/admin-ajax.php" {
			if readAction(r) == "ai1wm_export" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(loadFailed))
				return
			}
			// Every other action (including the random control probe) → "0".
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("0"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a generic load-failed HTML error page must not be flagged as an exposed AJAX action")
}

// TestScanPerRequest_NotWordPress ensures a non-WordPress host (admin-ajax.php
// returns an HTML shell, not the small "0" control body) is rejected.
func TestScanPerRequest_NotWordPress(t *testing.T) {
	t.Parallel()
	shell := "<!DOCTYPE html><html><head><title>App</title></head><body>" +
		"<div id=\"root\">single page app shell that renders for every route</div></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(shell)) // wildcard shell for every path
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-WordPress SPA shell must not yield a finding")
}
