package cms_installer_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_DetectsWordPressInstaller drives the real scan method
// against a host whose /wp-admin/install.php serves the WordPress setup wizard.
// The random 404 fingerprint path returns a distinct not-found page so the
// installer body is not mistaken for the 404 baseline.
func TestScanPerRequest_DetectsWordPressInstaller(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-admin/install.php" {
			_, _ = w.Write([]byte("<html><head><title>WordPress &rsaquo; Installation</title></head>" +
				"<body class=\"wp-install\"><form id=\"setup\"><select name=\"language\">" +
				"<option>en</option></select><a href=\"setup-config.php\">install.php</a></form></body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>nothing to see here, distinct 404 body padding padding padding</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a CMS installer finding when the WordPress installer is exposed")
}

// TestScanPerRequest_WeakWordNoFalsePositive ensures a normal 200 page that
// merely contains a generic word (here "language" and "database" in ordinary
// page copy/navigation) is NOT mistaken for an exposed installer. The old
// single-marker logic would have flagged this as a critical "WordPress
// Installer Exposed" because "language" was a standalone marker; the
// CMS-anchor + installer-context co-occurrence requirement rejects it.
func TestScanPerRequest_WeakWordNoFalsePositive(t *testing.T) {
	t.Parallel()
	page := "<html><head><title>Our Product</title></head><body>" +
		"<nav><a href=\"/language\">Language</a> <a href=\"/docs/database\">Database</a></nav>" +
		"<p>Choose your preferred language. Configure the database for installation.</p>" +
		"</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every installer path returns the same generic 200 marketing page;
		// the random 404-fingerprint path returns a distinct not-found body.
		switch r.URL.Path {
		case "/wp-admin/install.php", "/wp-admin/setup-config.php",
			"/install.php", "/core/install.php", "/installation/index.php":
			_, _ = w.Write([]byte(page))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>distinct 404 body padding padding padding</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a generic page containing a weak word must not be flagged as an exposed installer")
}

// TestScanPerRequest_TruncatedTailCatchAllNoFalsePositive reproduces the
// universal catch-all / echo FP class. The host answers EVERY path with a 200
// text/html body that is only a reflecting TAIL fragment (no leading
// <!DOCTYPE/<html>, as a gzip + bogus Content-Length:0 transport quirk would
// leave) carrying the WordPress installer markers plus the reflected request
// path. The per-path reflection defeats the 404 fingerprint (distinct
// hash/length) and the soft-404 gate, so only the extension-scoped decoy
// catch-all guard (MultiRoundExtDecoyCatchAll) rejects it: a decoy
// /wp-admin/vigolium-decoy-<rand>.php comes back 200 with the same markers,
// proving the "installer" is the host's wildcard shell.
func TestScanPerRequest_TruncatedTailCatchAllNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Truncated tail fragment: no <!doctype/<html>, reflects the path so every
		// path (fingerprint, installer, decoy) yields a DISTINCT body that still
		// carries the WordPress installer marker co-occurrence in the tail.
		_, _ = w.Write([]byte("</section><footer>rendered route " + r.URL.Path +
			" — WordPress installation process wp-install setup-config language-chooser</footer></body>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a truncated-tail catch-all echoing installer markers for every path must not be flagged")
}

// TestScanPerRequest_NoFalsePositive ensures a host that returns 404 for every
// installer path yields no finding.
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
	assert.Empty(t, res, "a host with no installer endpoints must not yield a finding")
}
