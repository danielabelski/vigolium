package bfla_detection

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// withHeader returns a copy of rr whose request carries the given header. BFLA
// credential-stripping tests only run against a request that actually presents
// credentials, so the authenticated baseline must carry an Authorization or
// Cookie header.
func withHeader(t *testing.T, rr *httpmsg.HttpRequestResponse, name, value string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw, err := httpmsg.AddOrReplaceHeader(rr.Request().Raw(), name, value)
	require.NoError(t, err)
	req := httpmsg.NewHttpRequestWithService(rr.Service(), raw)
	return httpmsg.NewHttpRequestResponse(req, rr.Response())
}

// redirectShell is the 200-OK soft login-redirect page a fronting gateway returns
// for every unauthenticated GET. It reflects the requested path into the first
// bytes (mirroring the real bsr.netflix.net response), which makes the byte-head
// wildcard guard miss it — each path produces a slightly different head.
func redirectShell(path string) string {
	return `<!DOCTYPE html>
<html>
  <head>
    <title>Redirecting...</title>
    <noscript>
      <meta http-equiv="refresh" content="0; url=/login?original_uri=` + url.PathEscape(path) + `" />
    </noscript>
  </head>
  <body>Redirecting to login...</body>
</html>`
}

// adminBody is the privileged page content. It is large enough that the full
// unauthenticated response (status line + headers + body) stays within 50% of
// the baseline body length, satisfying the module's isBodyLengthSimilar check.
var adminBody = "<html><body>Admin console: " + strings.Repeat("user record ", 80) + "</body></html>"

// TestScanPerRequest_DetectsBFLA drives the real scan method against an admin
// endpoint that serves the same privileged content whether or not the request
// carries Authorization/Cookie headers (broken function-level authorization).
// A distinct shell is returned for the wildcard probe so the finding isn't
// rejected as a wildcard match.
func TestScanPerRequest_DetectsBFLA(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Privileged content served regardless of auth headers.
		_, _ = w.Write([]byte(adminBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Seed an authenticated 2xx baseline for the admin path. The request must
	// carry a credential (here a session Cookie) or the auth-strip test is a no-op.
	rr := withHeader(t, modtest.Response(
		modtest.Request(t, srv.URL+"/admin/users"),
		"text/html",
		adminBody,
	), "Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a BFLA finding when the admin page is reachable without auth")
}

// bflaRandLetters returns a per-n unique run of non-hex letters (so the ratio
// normalizer, which collapses hex/digit runs, does not erase it) — used to make a
// response body's CONTENT genuinely differ on every request. An LCG mixes the seed
// through every position so distinct seeds yield disjoint strings (a plain
// seed%len pattern would repeat the same handful of words across requests).
func bflaRandLetters(n int64) string {
	const alpha = "ghijklmnopqrstuvwxyz"
	b := make([]byte, 24)
	x := uint64(n)*6364136223846793005 + 1442695040888963407
	for i := range b {
		x = x*6364136223846793005 + 1442695040888963407
		b[i] = alpha[(x>>40)%uint64(len(alpha))]
	}
	return string(b)
}

// TestScanPerRequest_MethodSwitchNonDeterministic reproduces the method-switch
// false positive: an admin path answers a switched, unauthenticated method
// (POST/PUT/DELETE) with a 2xx body that VARIES every request (a live dashboard /
// per-request token), differs from the random-path method-baseline, yet is not a
// privileged write. The reproduce control re-samples the switched method, sees the
// body fail to hold content-similar across samples, and drops it.
func TestScanPerRequest_MethodSwitchNonDeterministic(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			// Method-baseline probe path: distinct 404 so matchesMethodBaseline is false.
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "not found")
			return
		}
		if r.Method == "GET" {
			_, _ = io.WriteString(w, "<html><body>admin console landing overview page for reports</body></html>")
			return
		}
		// Switched write methods: a 2xx body whose CONTENT is substantially different
		// on every request (a non-deterministic endpoint), so two samples are not
		// content-similar and the response cannot be shown to reproduce.
		c := atomic.AddInt64(&n, 1)
		words := make([]string, 40)
		for i := range words {
			words[i] = bflaRandLetters(c*97 + int64(i))
		}
		_, _ = fmt.Fprintf(w, "<html><body>%s</body></html>", strings.Join(words, " "))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Bare GET, no credentials → testNoAuth/testDowngradedAuth bail; only the
	// method-switch leg runs. Attach a 2xx HTML baseline (required by ScanPerRequest).
	rr := modtest.Response(
		modtest.Request(t, srv.URL+"/admin/reports"),
		"text/html",
		"<html><body>admin console landing overview page for reports</body></html>",
	)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a switched-method response that varies every request (non-reproducible) must not be flagged as a BFLA bypass")
}

// TestScanPerRequest_NoFalsePositive ensures an admin endpoint that enforces
// authorization (401 once the Authorization/Cookie headers are stripped) yields
// no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Enforce auth: without credentials, deny.
		if r.Header.Get("Authorization") == "" && r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		_, _ = w.Write([]byte(adminBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// The baseline request is authenticated (carries a Cookie); stripping it must
	// trip the server's 401 and yield no finding.
	rr := withHeader(t, modtest.Response(
		modtest.Request(t, srv.URL+"/admin/users"),
		"text/html",
		adminBody,
	), "Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an admin page that requires auth must not yield a BFLA finding")
}

// TestScanPerRequest_LoginPageOnUnauthNoFalsePositive reproduces the loose-length
// false positive: stripping auth returns a 200 LOGIN page of similar LENGTH but
// entirely different CONTENT than the admin page. The old "body length within
// 50%" check flagged it; the content-similarity gate must reject it because the
// privileged content was not actually served unauthenticated.
func TestScanPerRequest_LoginPageOnUnauthNoFalsePositive(t *testing.T) {
	t.Parallel()
	loginBody := "<html><body>Please sign in to continue. " + strings.Repeat("username password forgot ", 35) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Only GET is enabled, so method-switching probes (POST/PUT/DELETE) get a
		// 405 and don't fire — isolating the auth-strip content check.
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Auth stripped → a 200 login page: similar size, totally different content.
		_, _ = w.Write([]byte(loginBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Seed the authenticated admin page as the baseline (carries a Cookie so the
	// auth-strip test actually runs and is then rejected on content dissimilarity).
	rr := withHeader(t, modtest.Response(modtest.Request(t, srv.URL+"/admin/users"), "text/html", adminBody),
		"Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 200 login page of similar length but different content must not be flagged as BFLA")
}

// TestScanPerRequest_CatchAllGatewayNoFalsePositive reproduces the bsr.netflix.net
// false positive: a fronting gateway accepts POST/PUT/DELETE for EVERY path with a
// uniform empty 200 (Content-Length: 0) and answers every unauthenticated GET with
// the same soft login-redirect shell. The old method-switching path flagged the
// empty 200 as a BFLA bypass because the byte-head wildcard guard does not match an
// empty body; the same-method baseline confirmation must reject it because "/",
// "/includes/", and the admin path all return the identical response.
func TestScanPerRequest_CatchAllGatewayNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Non-GET methods are accepted for every path with an empty 200.
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Every GET — admin path, sibling, root, or the random wildcard probe —
		// returns the same login-bounce shell.
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte(redirectShell(r.URL.Path)))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// The authenticated admin GET (carries a Cookie) also lands on the login
	// bounce, as in the report; the same-method baseline must drop it.
	adminPath := "/includes/admin-user-details-kp5deaqq"
	rr := withHeader(t, modtest.Response(
		modtest.Request(t, srv.URL+adminPath),
		"text/html",
		redirectShell(adminPath),
	), "Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all gateway returning the same response for every path/method must not be flagged as BFLA")
}

// TestScanPerRequest_PublicPageNoCredentialsNoFalsePositive reproduces the
// lp.globex.com false positive: an unauthenticated GET to a "/debug/" landing
// page returns 200, and "removing" the (absent) Authorization/Cookie headers
// trivially returns the same 200 because the request was never authenticated.
// The endpoint is simply public — there is no authorization to break — so a
// request that carried no credentials must not be tested for an auth-strip bypass.
func TestScanPerRequest_PublicPageNoCredentialsNoFalsePositive(t *testing.T) {
	t.Parallel()
	// A dynamic landing page: same template, content varies slightly per request
	// (as the report's 13985 vs 14389 body lengths show).
	landing := "<html><body>Globex landing page " + strings.Repeat("product highlight ", 90) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Only GET is served; method-switching probes get a 405 and don't fire,
		// isolating the auth-strip path that produced the report.
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte(landing))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// No Authorization, no Cookie — exactly the request from the report.
	rr := modtest.Response(modtest.Request(t, srv.URL+"/debug/"), "text/html", landing)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a public page reached without credentials must not be flagged as a BFLA auth bypass")
}

// TestScanPerRequest_CloudflareChallengeBaselineNoFalsePositive reproduces the
// 200-status WAF-challenge baseline false positive. BFLA deliberately targets
// admin paths, which carry the strictest, path-scoped WAF rules. A Cloudflare
// managed challenge served AT HTTP 200 (Cf-Mitigated) for /admin/users is the
// authenticated baseline; the auth-stripped probe hits the SAME 200 challenge (the
// edge ignores the credential) and is content-similar, while the random-path
// catch-all controls dodge the path-scoped rule (404) and cannot cancel it. The
// 200 status slips past the 2xx-baseline gate, so the edge-block gate must discard
// the challenge before any probing.
func TestScanPerRequest_CloudflareChallengeBaselineNoFalsePositive(t *testing.T) {
	t.Parallel()
	challenge := "<html><head><title>Just a moment...</title></head><body>" +
		strings.Repeat("Checking your browser before accessing the site. ", 20) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/users" {
			// Path-scoped Cloudflare challenge served at 200, auth-agnostic.
			w.Header().Set("Cf-Mitigated", "challenge")
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(challenge))
			return
		}
		// Every other path (catch-all / method-baseline controls) dodges the rule.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Seed the authenticated baseline as a 200 Cloudflare challenge (Cf-Mitigated),
	// carrying a credential so the auth-strip test would otherwise run.
	base := modtest.Request(t, srv.URL+"/admin/users")
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCf-Mitigated: challenge\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(challenge), challenge)
	rr := httpmsg.NewHttpRequestResponse(base.Request(), httpmsg.NewHttpResponse([]byte(rawResp)))
	rr = withHeader(t, rr, "Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a 200-status Cloudflare challenge baseline (Cf-Mitigated) must not be reported as a BFLA bypass")
}

// TestScanPerRequest_RandomizedContentNoFalsePositive guards the multi-sample
// reproduction check: the baseline request is authenticated (carries a Cookie),
// and the first auth-stripped probe happens to return privileged-looking content,
// but the endpoint flaps — subsequent requests return a different (login) page.
// A real bypass returns the privileged content every time; this coincidental
// single-sample match must be rejected.
func TestScanPerRequest_RandomizedContentNoFalsePositive(t *testing.T) {
	t.Parallel()
	const adminPath = "/admin/users"
	loginBody := "<html><body>Please sign in to continue. " + strings.Repeat("username password forgot ", 35) + "</body></html>"

	var mu sync.Mutex
	adminGETs := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "-vigolium-wp/") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != adminPath {
			// Wildcard probe and other paths get a neutral shell.
			_, _ = w.Write([]byte("<html><body>home</body></html>"))
			return
		}
		// First admin GET looks privileged; every later one flaps to a login page.
		mu.Lock()
		adminGETs++
		first := adminGETs == 1
		mu.Unlock()
		if first {
			_, _ = w.Write([]byte(adminBody))
			return
		}
		_, _ = w.Write([]byte(loginBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withHeader(t, modtest.Response(modtest.Request(t, srv.URL+adminPath), "text/html", adminBody),
		"Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a single coincidental privileged-content match that does not reproduce must not be flagged as BFLA")
}

// TestScanPerRequest_StaticImageAssetNoFalsePositive reproduces the
// media-assets.globex.com false positive: an Akamai/Scene7 image route whose
// path matches the admin heuristic only by substring ("/system" inside the
// "System Image" filename segment) serves a 200 WebP image to everyone. Stripping
// or switching auth returns the same image, so the old code flagged it. The
// content-type gate must drop the whole request before any sub-test runs.
func TestScanPerRequest_StaticImageAssetNoFalsePositive(t *testing.T) {
	t.Parallel()
	// A binary WebP payload, mirroring the report's RIFF....WEBP body.
	webp := "RIFF\x00\x00\x00\x00WEBPVP8 " + strings.Repeat("\x00\x01\x02\x03\xff\xfe", 64)
	const imgPath = "/is/image/globex/System Image"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The image path answers 200 for every method (CDN cache hit); all other
		// paths — the wildcard probe and the method baseline — 404. Without the
		// content-type gate this shape makes the method-switching test fire.
		if r.URL.Path != imgPath {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "image/webp")
		_, _ = w.Write([]byte(webp))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/is/image/globex/System%20Image"), "image/webp", webp)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a static image asset must never be flagged as a BFLA privileged endpoint")
}

// TestScanPerRequest_EmptyPrivilegedBaselineNoFalsePositive reproduces the
// globex-agile.atlassian.net /secure/ConfigureReport.jspa false positive: a JSP
// action endpoint (matched as "admin" via the "/config" substring in
// "/configurereport") answers an unauthenticated request with an empty 200
// (Content-Length: 0) for both GET and POST, while a random nonexistent path
// 404s — so the same-method baseline guard does not match and the empty 200 was
// flagged as a BFLA method-switch bypass. An empty privileged baseline carries no
// content to reproduce, so the whole request must be skipped.
func TestScanPerRequest_EmptyPrivilegedBaselineNoFalsePositive(t *testing.T) {
	t.Parallel()
	const adminPath = "/secure/ConfigureReport.jspa"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != adminPath {
			// Random wildcard / method-baseline probes hit the app's 404 with a body,
			// so the same-method baseline differs from the admin path's empty 200.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// The action handler swallows GET and POST alike with an empty 200.
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// Exactly the report: an unauthenticated GET to the .jspa path, empty body.
	rr := modtest.Response(modtest.Request(t, srv.URL+adminPath), "text/html;charset=utf-8", "")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an endpoint whose privileged baseline is an empty 200 must not be flagged as BFLA")
}

// TestScanPerRequest_MethodSwitchEmptyBodyNoFalsePositive guards the
// method-switching empty-body case: the admin GET baseline carries real content,
// but switching to POST returns an empty 2xx (a gateway/handler swallowing the
// request). An empty switched-method response is not evidence the privileged
// function executed and must not be flagged.
func TestScanPerRequest_MethodSwitchEmptyBodyNoFalsePositive(t *testing.T) {
	t.Parallel()
	const adminPath = "/admin/config"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != adminPath {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		if r.Method != http.MethodGet {
			// Non-GET methods are accepted with an empty 200 — no content executed.
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte(adminBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	// No credentials (as in the report), so only the method-switching test runs.
	rr := modtest.Response(modtest.Request(t, srv.URL+adminPath), "text/html", adminBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a method switch returning an empty 2xx must not be flagged as BFLA")
}

// TestScanPerRequest_BinaryBodyMislabeledNoFalsePositive guards the binary-body
// sniff fallback: a binary asset mislabeled with a text Content-Type (a CDN bug)
// must still be skipped, since the content-type allow-list alone would let it
// through.
func TestScanPerRequest_BinaryBodyMislabeledNoFalsePositive(t *testing.T) {
	t.Parallel()
	binary := "\x00\x01\x02\x03\x00\xff\xfe\x00" + strings.Repeat("\x00\x10\x20\x7f", 200)
	const p = "/system/blob"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != p {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Mislabeled as HTML, but the body is binary.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(binary))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+p), "text/html", binary)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a binary body mislabeled as text must be skipped via the body sniff")
}

// TestScanPerRequest_MethodSwitchDetectsWithCredentials is the positive control
// for the same-representation guard added below: when the original GET *did*
// carry credentials, an unauthenticated POST returning that same privileged
// content is the bypass, not a false positive, and must still be reported.
func TestScanPerRequest_MethodSwitchDetectsWithCredentials(t *testing.T) {
	t.Parallel()
	const adminPath = "/admin/config"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != adminPath {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// GET requires the session cookie; POST is served to anyone.
		if r.Method == http.MethodGet && r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
			return
		}
		_, _ = w.Write([]byte(adminBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := withHeader(t, modtest.Response(
		modtest.Request(t, srv.URL+adminPath), "text/html", adminBody,
	), "Cookie", "session=valid-session-token")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "an unauthenticated POST returning the credentialed page is a real bypass")
}

// TestScanPerRequest_MethodSwitchSameRepresentationNoFalsePositive covers the
// shape shared by two production false positives: an endpoint that needed no
// credentials in the first place and answers POST with byte-identical content to
// the GET. The server simply ignores the method for that route, so nothing about
// function-level authorization has been demonstrated. The response is explicitly
// no-store and the wildcard/method baselines differ, so only the
// same-representation guard can reject it.
func TestScanPerRequest_MethodSwitchSameRepresentationNoFalsePositive(t *testing.T) {
	t.Parallel()
	const adminPath = "/admin/portal"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != adminPath {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		// Same representation for every method — the route is method-agnostic.
		_, _ = w.Write([]byte(adminBody))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+adminPath), "text/html", adminBody)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a method-agnostic public route must not be flagged as a BFLA bypass")
}

// TestScanPerRequest_HealthProbeNoFalsePositive mirrors the production false
// positive on //actuator/healthcheck: a health probe returning `<health>ok</health>`
// to every method was reported as a High authorization bypass. Health/liveness
// endpoints are public by design and expose no privileged function.
func TestScanPerRequest_HealthProbeNoFalsePositive(t *testing.T) {
	t.Parallel()
	const health = "<health>ok</health>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/actuator/healthcheck") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(health))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/actuator/healthcheck"), "application/xml", health)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a health probe is public by design and is not a privileged function")
}

// tableauErrorPage is the static "something went wrong" page Tableau ships as a
// file at /vizportalclient/internalServerError.var — served with a one-year TTL
// and validators, and identical for every method.
var tableauErrorPage = "<!DOCTYPE html><html><head><title>An unexpected error occurred</title></head>" +
	"<body><h1>Uh oh! Something went wrong.</h1>" + strings.Repeat("<p>An unexpected error occurred.</p>", 20) + "</body></html>"

// TestScanPerRequest_StaticErrorPageNoFalsePositive mirrors the production false
// positive on /vizportalclient/internalServerError.var: a cacheable static error
// page whose filename merely *starts* with the "/internal" admin pattern, and
// which — being a file — answers POST with the same bytes as GET.
func TestScanPerRequest_StaticErrorPageNoFalsePositive(t *testing.T) {
	t.Parallel()
	const p = "/vizportalclient/internalServerError.var"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != p {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Cache-Control", "max-age=31536000")
		w.Header().Set("Etag", `"132-6538062df8900"`)
		w.Header().Set("Accept-Ranges", "bytes")
		_, _ = w.Write([]byte(tableauErrorPage))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+p+"?requestId=am1Aa72GGHjQLkJwCbx5Mg"), "text/html", tableauErrorPage)

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a cacheable static error page is not a privileged endpoint")
}

// TestIsAdminPath_SegmentBoundary pins the anchoring rules: an admin pattern must
// end at a word boundary, so it still matches its own segment and ordinary
// suffixes, but never the leading word of a longer camelCase or space-separated
// identifier.
func TestIsAdminPath_SegmentBoundary(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/admin", true},
		{"/admin/users", true},
		{"/admin-panel/users", true},
		{"/administration/users", true},
		{"/api/v1/admin/reports", true},
		{"/actuator/env", true},
		{"/internal/status", true},
		{"/internal-api/keys", true},
		{"/debug/pprof", true},
		// Pattern is only the first camelCase word of a filename.
		{"/vizportalclient/internalServerError.var", false},
		{"/js/configLoader.js", false},
		{"/app/systemStatus", false},
		// Pattern followed by a space belongs to a multi-word filename.
		{"/is/image/globex/System Image", false},
		// No pattern at all.
		{"/index.html", false},
		{"/products/42", false},
	} {
		assert.Equalf(t, tc.want, isAdminPath(tc.path), "isAdminPath(%q)", tc.path)
	}
}

// TestLooksCacheableStatic pins the cache-header heuristic that separates a
// shipped artifact from a rendered privileged response.
func TestLooksCacheableStatic(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		headers string
		want    bool
	}{
		{"long ttl with validator", "Cache-Control: max-age=31536000\r\nEtag: \"abc\"\r\n", true},
		{"long ttl with last-modified", "Cache-Control: public, max-age=86400\r\nLast-Modified: Fri, 05 Jun 2026 11:59:00 GMT\r\n", true},
		{"long ttl but no validator", "Cache-Control: max-age=31536000\r\n", false},
		{"short ttl", "Cache-Control: max-age=60\r\nEtag: \"abc\"\r\n", false},
		{"private", "Cache-Control: private, max-age=31536000\r\nEtag: \"abc\"\r\n", false},
		{"no-store", "Cache-Control: no-store\r\nEtag: \"abc\"\r\n", false},
		{"no cache-control", "Etag: \"abc\"\r\n", false},
		{"sets a session cookie", "Cache-Control: max-age=31536000\r\nEtag: \"abc\"\r\nSet-Cookie: s=1\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "HTTP/1.1 200 OK\r\n" + tc.headers + "Content-Type: text/html\r\n\r\nbody"
			assert.Equal(t, tc.want, looksCacheableStatic(httpmsg.NewHttpResponse([]byte(raw))))
		})
	}
}
