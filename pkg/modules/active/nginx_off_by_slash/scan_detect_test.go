package nginx_off_by_slash

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const obsSecret = "<html><body>SECRET ALIASED DIRECTORY LISTING: db.conf app.py settings.py</body></html>"

// TestScanPerRequest_DetectsStableOffBySlash fires when an alias-traversal path
// resolves to a SPECIFIC resource outside the alias dir: the escaped path
// returns a stable, distinct 200 while the in-alias equivalent, a random-suffix
// traversal, and the wildcard probe all 404. The response genuinely depends on
// the traversed path — the hallmark of a real off-by-slash.
func TestScanPerRequest_DetectsStableOffBySlash(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the specific escaped path (segment "images" → first suffix
		// "static", i.e. /images../static, mapping to the parent /static dir)
		// resolves; everything else — /images/static, /images../<random>, the
		// wildcard probe — 404s.
		if r.URL.Path == "/images../static" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(obsSecret))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/images/list"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a stable distinct 200 on an alias-traversal path must be reported")
}

// TestScanPerRequest_NoFalsePositive_BinaryImageCDN guards the path_normalization
// FP class for this module: an extensionless image-CDN URL (Scene7/Akamai shape)
// passes the URL-extension filter, and its alias-traversal path returns a stable
// 200 image/webp. Binary/static-asset content is the static handler simply
// serving a file (and its bytes are not stable on re-optimizing CDNs), so it must
// be excluded by the response Content-Type gate — no finding. Without that gate
// this exact shape (stable distinct 200, in-alias + random + wildcard all 404)
// would be reported.
func TestScanPerRequest_NoFalsePositive_BinaryImageCDN(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/images../static" {
			w.Header().Set("Content-Type", "image/webp")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("RIFF" + strings.Repeat("x", 200) + "WEBP"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/images/render"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a binary image/webp alias-traversal response must not be flagged")
}

// TestScanPerRequest_NoFalsePositive_GenericPrefixResponse reproduces the
// reported false positive: a prefixed auth middleware / API gateway returns one
// generic body (`{"message":"User not logged in"}`) for the ENTIRE /api path
// space, so /api../content "succeeds" only because /api/content — and indeed
// /api/anything — returns the identical shell. The ".." escaped nothing. The
// wildcard probe (a path outside /api) 404s and cannot catch this; only the
// differential gate against the in-alias equivalent does.
func TestScanPerRequest_NoFalsePositive_GenericPrefixResponse(t *testing.T) {
	t.Parallel()
	const authWall = `{"code":10001,"message":"User not logged in","data":{},"nowTime":"2026-06-05 02:52:22"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generic 200 for any path under /api (mirrors a prefix-scoped auth
		// middleware); anything else — including the wildcard probe — 404s.
		if strings.HasPrefix(r.URL.Path, "/api") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(authWall))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/api/content"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a prefix-wide generic response identical to the in-alias path must not be reported")
}

// TestScanPerRequest_NoFalsePositive_SuffixInvariantCatchAll covers a catch-all
// that serves the same 200 for any suffix under the escaped prefix while the
// in-alias path 404s: /seg../<anything> all return one shell, so the body does
// not depend on the suffix and no real file is being read.
func TestScanPerRequest_NoFalsePositive_SuffixInvariantCatchAll(t *testing.T) {
	t.Parallel()
	const shell = "<html><body>application landing shell — same for every escaped path</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any traversal suffix resolves to one shell (suffix-invariant); the
		// in-alias equivalent and the wildcard probe 404.
		if strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(shell))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/static/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a suffix-invariant catch-all under the escaped prefix must not be reported")
}

// TestScanPerRequest_NoFalsePositive_PublicAtWebRoot reproduces the
// static-root-traversal FP class for this module: the front-end normalizes
// /images../api down to /api, which the host already serves publicly at the web
// root. The escape is suffix-specific (only /api resolves, a random suffix 404s)
// and the in-alias /images/api 404s — so the stability, in-alias-differential,
// and random-suffix controls all pass. Only the clean-canonical control (does
// plain /api serve the same body?) catches that nothing was actually escaped.
func TestScanPerRequest_NoFalsePositive_PublicAtWebRoot(t *testing.T) {
	t.Parallel()
	const publicAPI = `{"service":"orders","status":"ok","endpoints":["/list","/create","/cancel"],"version":"3.1.0"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both the escaped path and the clean canonical /api serve the same
		// public resource; a random suffix and the in-alias path 404.
		if r.URL.Path == "/images../api" || r.URL.Path == "/api" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(publicAPI))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/images/render"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an escape that resolves to a path already served publicly at the web root must not be reported")
}

// TestScanPerRequest_NoFalsePositive_WildcardSPAShell reproduces a reported
// /api../source false positive on a wildcard SPA host: the app serves one
// identical Angular index.html shell for EVERY unknown path (/, /api../source,
// /api../<random> and a random web-root directory all return it), while the one
// real API route /api/source answers 403. On the live WAF/CDN-fronted host the
// per-suffix differential controls each flaked to a non-2xx and fail-closed
// toward "escaped", so the finding slipped through. This test models that: the
// wildcard probe, the in-alias /api/source, the random-suffix and the
// clean-canonical controls are all defeated (non-2xx), so ONLY the positive
// catch-all/SPA-shell guard — which samples the site root and a random web-root
// directory independently — can drop it.
func TestScanPerRequest_NoFalsePositive_WildcardSPAShell(t *testing.T) {
	t.Parallel()
	const shell = "<!doctype html><html lang=\"en\" data-beasties-container><head><title>Acme Portal</title></head><body><app-root></app-root></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		// The one real API route answers 403 (defeats the in-alias differential,
		// which fails closed on a non-2xx control — exactly the live host).
		case p == "/api/source":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":403,"message":"forbidden"}`))
			return
		// The wildcard probe and the fragile per-suffix controls (random suffix
		// under the escaped prefix, clean-canonical /source) are throttled to a
		// 404 — the scan-time flake that disabled every existing gate.
		case strings.Contains(p, "-vigolium-wp"):
		case strings.HasPrefix(p, "/api../") && p != "/api../source":
		case p == "/source":
		default:
			// Everything else — the hit /api../source, the site root "/", and the
			// random web-root directory the catch-all guard probes — is the shell.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(shell))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/api/list"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a wildcard SPA shell served for every path must not be reported even when the differential controls are throttled")
}

// TestScanPerRequest_NoFalsePositive_TransientOffBySlash reproduces a one-shot
// 200: only the very first alias-traversal request succeeds, then 404s. The
// multi-round stability gate must drop it.
func TestScanPerRequest_NoFalsePositive_TransientOffBySlash(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	served := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") {
			mu.Lock()
			first := !served
			served = true
			mu.Unlock()
			if first {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(obsSecret))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/static/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a one-shot transient 200 that does not reproduce must not be reported")
}
