package laravel_sensitive_files

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

// laravelHandler serves a telltale Laravel artisan script for /artisan and a
// distinct 404 body for everything else (including the module's random 404
// fingerprint probe), so the response for the real probe diverges from the
// fingerprinted not-found page.
func laravelHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/artisan" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("#!/usr/bin/env php\n<?php\n// artisan\nuse Illuminate\\Foundation\\Application;\n$app = new Application();\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}
}

// TestScanPerRequest_DetectsArtisan drives the real scan method against a host
// that exposes the Laravel artisan script (wrong document root) and asserts the
// module reports a finding.
func TestScanPerRequest_DetectsArtisan(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(laravelHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>home</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when /artisan is web-reachable")
	assert.True(t, strings.Contains(res[0].Info.Name, "Artisan"), "finding should name the artisan probe")
}

// TestScanPerRequest_NoFalsePositive ensures a host that returns 404 for every
// probed Laravel path yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>home</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host with no exposed Laravel files must not yield a finding")
}

// TestScanPerRequest_NoFP_TruncatedHTMLReflector reproduces the acme
// trace.acme.com catch-all: every path returns 200 text/html echoing the
// request, but a gzip/Content-Length:0 quirk left only a truncated tail (no
// leading <!DOCTYPE/<html>), so the anti-markers are gone yet weak markers
// ("Application", "bootstrap", "name", "version") survive. A Laravel config /
// source / db file is never served as an HTML document, so the content-type gate
// must suppress every finding.
func TestScanPerRequest_NoFP_TruncatedHTMLReflector(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Tail fragment of a request-echo page: weak markers present, no doctype/head.
		_, _ = w.Write([]byte(`<tr><td>uri</td><td>` + r.URL.Path + `</td></tr>` +
			`<div>Application bootstrap name version packages Route::</div>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<tr>echo</tr>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a truncated text/html echo page must not be flagged as an exposed Laravel file")
}

// TestScanPerRequest_NoFP_TextReflector covers a catch-all that answers every
// path with 200 text/plain carrying the markers (content-type gate passes), so
// only the multi-round same-extension decoy disproof can catch it: a random
// sibling returns the same marker-bearing body, proving the host serves it for
// any path.
func TestScanPerRequest_NoFP_TextReflector(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// Path-dependent, variable-length body so the 404-fingerprint hash/length
		// and body-similarity guards do not fire — only the same-extension decoy,
		// run through the marker predicate, can prove this is a catch-all.
		_, _ = w.Write([]byte("#!/usr/bin/env php\nuse Illuminate\\Foundation\\Application; artisan bootstrap for " +
			r.URL.Path + strings.Repeat("x", len(r.URL.Path))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>home</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a text/plain echo/catch-all must be disproved by the same-extension decoy")
}

// TestScanPerRequest_NoFP_StructuredFileAsHTMLDocument isolates the content-type
// gate. A structured Laravel file (composer's installed.json — genuine content is
// JSON, never an HTML *document*) is served as 200 text/html ONLY at its own path,
// with every sibling 404. The tail-fragment body carries the weak markers
// ("packages", "name", "version", "laravel/framework") but no <!DOCTYPE/<html>, so
// the anti-markers cannot fire and the 404-fingerprint diverges. Because the
// siblings 404, the multi-round decoy catch-all disproof does NOT fire here — so
// the truncation-proof content-type gate (a JSON file coming back as an HTML
// document is the catch-all/echo shell, not the real file) is the SOLE guard that
// must suppress the finding.
func TestScanPerRequest_NoFP_StructuredFileAsHTMLDocument(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vendor/composer/installed.json" {
			// Wrong content-type: a truncated HTML tail (no doctype/html tag) that
			// carries the weak markers as prose. Served ONLY at the real path.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<span>packages</span> name version laravel/framework loaded`))
			return
		}
		// Every other path (the 404 fingerprint probe AND the decoy siblings) 404s,
		// so the decoy catch-all disproof cannot fire — only the content-type gate can.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a structured Laravel file served as an HTML document must be rejected by the content-type gate")
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
