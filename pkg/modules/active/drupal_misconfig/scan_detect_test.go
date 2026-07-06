package drupal_misconfig

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsExposedChangelog drives the real scan method against
// a host that serves /CHANGELOG.txt, leaking the exact Drupal core version. The
// random 404 fingerprint path returns a distinct not-found body.
func TestScanPerRequest_DetectsExposedChangelog(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/CHANGELOG.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Drupal 7.92, 2022-06-01\n----------------------\n" +
				"Changes since 7.91:\n- Bug fixes and improvements.\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>The requested page could not be found, distinct 404 body.</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a Drupal misconfig finding when CHANGELOG.txt is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures a host returning 404 for every
// Drupal-specific path yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>404 Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-Drupal host must not yield a finding")
}

// catchAllShell is a themed SPA / catch-all application shell that returns 200
// with the same body for almost any path. It contains the generic words the
// old single-marker probes keyed on ("update", "install", "database") but no
// Drupal-identity anchor — exactly the vn.einvoice.initech.com case. A distinct
// body is served for the random 404-fingerprint path so the fingerprint alone
// cannot suppress the finding; the co-occurrence markers and baseline-shell
// guard must.
const catchAllShell = `<!DOCTYPE html><html><head><title>Hóa đơn điện tử</title>` +
	`<script src="/Content/js/update-bundle.js"></script></head><body>` +
	`<nav><a href="/tai-khoan/dang-nhap">Đăng nhập</a>` +
	`<a href="/install">Cài đặt</a><a href="/database/search">Tra cứu</a></nav>` +
	`<main>Welcome to the invoice portal. Please sign in to continue.</main></body></html>`

// TestScanPerRequest_CatchAllShellNoFalsePositive reproduces the
// vn.einvoice.initech.com false positive: an ASP.NET catch-all that 200s every
// path with the same app shell (containing weak words like "update"/"install")
// must not be reported as an exposed Drupal endpoint, because no Drupal-identity
// anchor co-occurs.
func TestScanPerRequest_CatchAllShellNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "vigolium-drupal-404-") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><body>The requested page could not be found.</body></html>"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(catchAllShell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/tai-khoan/quen-mat-khau/"), "text/html", catchAllShell)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all app shell with no Drupal-identity anchor must not yield a finding")
}

// TestScanPerRequest_BaselineShellGuard isolates the baseline-shell guard: even
// when a catch-all body satisfies the co-occurrence markers (it contains both
// "Drupal" and "database update"), the finding is dropped because the probe
// response is textually equivalent to the originally-observed page — the body is
// "the same with or without the payload".
func TestScanPerRequest_BaselineShellGuard(t *testing.T) {
	t.Parallel()
	shell := `<!DOCTYPE html><html><head><title>Drupal portal</title></head><body>` +
		`<p>This page mentions Drupal database update workflows in its help text.</p>` +
		`<nav><a href="/home">Home</a><a href="/about">About</a></nav></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "vigolium-drupal-404-") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><body>distinct not found body, nothing like the shell.</body></html>"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(shell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", shell)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a probe body equal to the observed page shell must be dropped by the baseline-shell guard")
}
