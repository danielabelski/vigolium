package lfi_path_traversal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// passwdBody is a realistic /etc/passwd dump carrying the module's markers
// (`root:`, `:0:0:`, `/bin/`).
const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" +
	"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
	"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
	"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n" +
	"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"

// cleanBaseline is a marker-free baseline page, comfortably shorter than
// passwdBody so the traversal response clears the minimum body-delta gate.
const cleanBaseline = "<html><body>Welcome — choose a document to view.</body></html>"

// cfBlockBody is the body of the Cloudflare "Blocked Content Notification" 403
// that produced the original false positive: its embedded cf-beacon JSON carries
// "server_timing" and "location_startswith", which satisfied the former bare
// "server"/"location" nginx.conf markers.
const cfBlockBody = `<!DOCTYPE html><html><head><title>Blocked</title></head><body>
<h1>Blocked Content Notification</h1>
<p>The website you are trying to visit has been blocked.</p>
<script defer src="https://static.cloudflareinsights.com/beacon.min.js"
 data-cf-beacon='{"version":"2024.11.0","token":"bb500abe","server_timing":{"name":{"cfEdge":true,"cfOrigin":true}},"location_startswith":null}'></script>
</body></html>`

// TestScanPerInsertionPoint_DetectsPasswd drives the real scan method against a
// server that returns passwd content on traversal. The clean baseline (attached
// as the captured response) carries no passwd lines, so the structural confirmer
// counts every line as new and a finding is produced.
func TestScanPerInsertionPoint_DetectsPasswd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("file")
		if strings.Contains(v, "..") || strings.Contains(v, "etc/passwd") {
			_, _ = io.WriteString(w, passwdBody)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/?file=welcome"), "text/html", cleanBaseline)
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an LFI finding: passwd markers absent from baseline, present after traversal")
}

// TestScanPerInsertionPoint_NoMarkersNoFinding exercises the confirmation gate:
// the traversal response is long enough to clear the body-delta gate but
// contains no passwd content, so the structural confirmer returns false and no
// finding is produced. (A delta-only test would pass even with broken confirm
// logic; this one reaches the confirmer.)
func TestScanPerInsertionPoint_NoMarkersNoFinding(t *testing.T) {
	longNoMarkerBody := "<html><body>" + strings.Repeat("error: file not found. ", 20) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, longNoMarkerBody) // long, but no root:/:0:0:/bin/ markers
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/?file=welcome"), "text/html", cleanBaseline)
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a long response without passwd markers must not yield an LFI finding")
}

// TestScanPerInsertionPoint_MarkersAlreadyInBaseline exercises the
// baseline-subtraction false-positive defense: the passwd lines are already
// present in the captured baseline (a page that legitimately renders a passwd
// dump), so even though the traversal response is longer (clears the delta gate)
// and still contains them, the structural confirmer subtracts the baseline
// occurrences and reports zero NEW lines — no finding.
func TestScanPerInsertionPoint_MarkersAlreadyInBaseline(t *testing.T) {
	// Baseline already renders the passwd dump line-anchored (e.g. a tutorial).
	const markerBaseline = passwdBody
	// Traversal response = same content + >=50 bytes of padding, so it clears the
	// body-delta gate but introduces no NEW passwd lines.
	body := markerBaseline + strings.Repeat("x", 80)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/?file=welcome"), "text/html", markerBaseline)
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "passwd lines already present in the baseline must be subtracted, not reported as LFI")
}

// TestScanPerInsertionPoint_CloudflareBlockNoFinding is the regression for the
// reported false positive: a Cloudflare 403 "Blocked Content" page (Server:
// cloudflare) whose body carries no real file content must never be reported as
// LFI, even though its embedded cf-beacon JSON contains the tokens that
// satisfied the old bare "server"/"location" nginx.conf markers. The WAF-block
// gate rejects the 403 before any confirmer runs, and the rejection does not
// count as a status change, so tier-2 (nginx.conf et al.) is never escalated.
func TestScanPerInsertionPoint_CloudflareBlockNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("file")
		if strings.Contains(v, "..") || strings.Contains(v, "etc/") {
			w.Header().Set("Server", "cloudflare")
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, cfBlockBody)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/?file=welcome"), "text/html", cleanBaseline)
	ip := modtest.InsertionPoint(t, rr, "file")

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a Cloudflare 403 block page must never be reported as LFI")
}

// publishedDotenv is a .env genuinely deployed into the served directory — the
// shape a static-site build routinely ships into an S3 bucket. Its assignments
// satisfy filesig.ConfirmDotenv, which is precisely why the body alone cannot
// say whether it was included or simply fetched.
const publishedDotenv = "APP_NAME=Storefront\nAPP_ENV=production\nAPP_KEY=base64:2Fh8qLd9\n" +
	"DB_CONNECTION=mysql\nDB_HOST=db.internal\nDB_USERNAME=storefront\nDB_PASSWORD=s3cr3t-value\n" +
	"MAIL_PASSWORD=another-secret\nREDIS_PASSWORD=cache-secret\n"

// TestScanPerInsertionPoint_PathPointDocrootFileDowngradesToInfo covers the same
// class the sibling lfi-generic module hit in production, reached here through
// tier 2: `../../../../.env` injected into a URL *path* segment normalizes back
// to a plain `/.env` fetch, so a published .env confirms as file content without
// any inclusion having happened. The exposure is reported, but as informational.
func TestScanPerInsertionPoint_PathPointDocrootFileDowngradesToInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, ".env"):
			_, _ = io.WriteString(w, publishedDotenv)
		case strings.Contains(r.URL.Path, "etc/passwd"), strings.Contains(r.URL.Path, "win.ini"):
			// Served, but with a different status and no file content: this is what
			// unlocks tier 2 without confirming tier 1.
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, strings.Repeat("no such document here. ", 20))
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/docs/report.pdf"), "text/html", cleanBaseline)
	ip := modtest.InsertionPointByType(t, rr, httpmsg.INS_URL_PATH_FILENAME)

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "the exposure is still worth reporting")
	assert.Equal(t, severity.Info, res[0].Info.Severity,
		"a published .env fetched by its own URL is exposure, not path traversal")
	assert.Contains(t, res[0].URL, ".env", "the finding must point at the exposed file")
}

// TestScanPerInsertionPoint_PathPointOSFileKeepsHigh is the counterpart: no web
// root serves /etc/passwd, so reaching it from a path segment really is an
// escape and must keep the module's High severity.
func TestScanPerInsertionPoint_PathPointOSFileKeepsHigh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "etc/passwd") {
			_, _ = io.WriteString(w, passwdBody)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/docs/report.pdf"), "text/html", cleanBaseline)
	ip := modtest.InsertionPointByType(t, rr, httpmsg.INS_URL_PATH_FILENAME)

	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, severity.High, res[0].Info.Severity,
		"an OS file reached from a path segment is a genuine traversal")
}
