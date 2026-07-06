package magento_misconfig

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

// magentoHandler serves an exposed Magento 1.x local.xml for /app/etc/local.xml
// and a distinct 404 body for everything else (including the random 404
// fingerprint probe), so the real probe response diverges from the not-found
// fingerprint.
func magentoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/etc/local.xml" {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?>
<config>
  <global>
    <resources>
      <default_setup>
        <connection>
          <dbname><![CDATA[magento]]></dbname>
        </connection>
      </default_setup>
    </resources>
    <crypt><key><![CDATA[deadbeef]]></key></crypt>
  </global>
</config>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}
}

// TestScanPerRequest_DetectsLocalXML drives the real scan method against a host
// that exposes Magento's local.xml and asserts the module reports a finding.
func TestScanPerRequest_DetectsLocalXML(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(magentoHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>store</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when local.xml is web-reachable")
	assert.True(t, strings.Contains(res[0].Info.Name, "Configuration"), "finding should name the config probe")
}

// TestScanPerRequest_NoFalsePositive ensures a host returning 404 for every
// probed Magento path yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>store</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed Magento files must not yield a finding")
}

// magentoCatchAllShell is a themed SPA / catch-all application shell that 200s
// almost any path with the same body. It contains the generic words the old
// single-marker probes keyed on ("setup", "downloader") but no Magento-identity
// anchor — the vn.einvoice.initech.com case.
const magentoCatchAllShell = `<!DOCTYPE html><html><head><title>Hóa đơn điện tử</title>` +
	`<script src="/Content/js/setup-downloader.js"></script></head><body>` +
	`<nav><a href="/hoa-don/tra-cuu">Tra cứu</a><a href="/admin">Quản trị</a></nav>` +
	`<main>Welcome to the invoice portal. Please sign in to continue.</main></body></html>`

// TestScanPerRequest_CatchAllShellNoFalsePositive reproduces the
// vn.einvoice.initech.com false positive: an ASP.NET catch-all that 200s every
// path with the same app shell (containing weak words like "setup"/"downloader")
// must not be reported as an exposed Magento endpoint, because no Magento-identity
// anchor co-occurs.
func TestScanPerRequest_CatchAllShellNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "vigolium-magento-404-") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><body>The requested page could not be found.</body></html>"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(magentoCatchAllShell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/hoa-don/tra-cuu/"), "text/html", magentoCatchAllShell)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all app shell with no Magento-identity anchor must not yield a finding")
}

// TestScanPerRequest_BaselineShellGuard isolates the baseline-shell guard: even
// when a catch-all body satisfies the co-occurrence markers (it contains both
// "Magento" and "Setup Wizard"), the finding is dropped because the probe
// response is textually equivalent to the originally-observed page.
func TestScanPerRequest_BaselineShellGuard(t *testing.T) {
	t.Parallel()
	shell := `<!DOCTYPE html><html><head><title>Magento store</title></head><body>` +
		`<p>Our Setup Wizard help center explains how Magento works.</p>` +
		`<nav><a href="/home">Home</a><a href="/about">About</a></nav></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "vigolium-magento-404-") {
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

// TestScanPerRequest_DeployedVersionConfirmed serves a real Magento
// deployed_version.txt (a bare timestamp token) and asserts the Info finding
// fires on the version-token shape.
func TestScanPerRequest_DeployedVersionConfirmed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/deployed_version.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("1530000000"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>store</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an Info finding when deployed_version.txt holds a version token")
	assert.True(t, strings.Contains(res[0].Info.Name, "Deployed Version"))
}

// TestScanPerRequest_DeployedVersionGenericBodyNoFalsePositive reproduces the
// "." marker false positive: a small non-version 200 text body (prose with
// spaces) on the version path must not yield a finding. The old "." marker
// matched any non-empty body; the version-token regex rejects whitespace-laden
// prose.
func TestScanPerRequest_DeployedVersionGenericBodyNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/deployed_version.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Welcome to our store homepage"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>store</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-version text body on deployed_version.txt must not yield a finding")
}

// TestCanProcess covers the custom CanProcess gate: a request needs a response.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	m := New()
	assert.False(t, m.CanProcess(nil))

	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, m.CanProcess(rr), "no baseline response means not processable")

	withResp := modtest.Response(rr, "text/html", "ok")
	assert.True(t, m.CanProcess(withResp))
}
