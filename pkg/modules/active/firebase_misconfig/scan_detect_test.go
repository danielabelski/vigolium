package firebase_misconfig

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

// TestScanPerRequest_DetectsInitJSON serves the Firebase Hosting init.json
// reserved URL with project-config markers, which the module should flag.
func TestScanPerRequest_DetectsInitJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__/firebase/init.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"projectId":"demo-app","apiKey":"AIzaXXXX","authDomain":"demo.firebaseapp.com",` +
				`"storageBucket":"demo.appspot.com","messagingSenderId":"123456789"}` +
				strings.Repeat(" ", 200)))
			return
		}
		// Distinct short 404 so the body fingerprint diverges from init.json.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when Firebase init.json config is exposed")
}

// TestScanPerRequest_NoFalsePositive returns a generic SPA page for every probe
// path; anti-markers (HTML doctype) and 404 fingerprinting must suppress findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body>SPA fallback</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an HTML SPA fallback must not be flagged as exposed config")
}

// TestScanPerRequest_NoFP_TruncatedHTMLReflector reproduces the acme
// trace.acme.com catch-all: every path returns 200 text/html echoing the
// request, but a gzip/Content-Length:0 transport quirk left only a truncated
// *tail* of the body — so the leading "<!DOCTYPE"/"<html" the anti-markers key
// on is gone, yet weak markers ("{", `":`) survive in the tail. The content-type
// header (text/html) is intact and must suppress the finding: a Firebase config
// file is never served as an HTML document.
func TestScanPerRequest_NoFP_TruncatedHTMLReflector(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// A tail fragment of a request-echo page: no doctype/<html head, but it
		// carries "{" and `":` (from an inline JSON script + the reflected path)
		// that the weak .runtimeconfig.json markers would otherwise match.
		_, _ = w.Write([]byte(`<tr><td>requested</td><td>` + r.URL.Path + `</td></tr>` +
			`<script>fetch('/x',{body:JSON.stringify({"scheme":"https"})})</script>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<tr>echo</tr>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a truncated text/html echo page must not be flagged as Firebase config")
}

// TestScanPerRequest_NoFP_JSONReflector covers a catch-all that (unlike the HTML
// reflector) answers every path with 200 application/json echoing the request —
// so the content-type gate passes and only the multi-round same-extension decoy
// disproof can catch it: a random /vigolium-decoy-*.json returns the same
// marker-bearing JSON, proving the host serves it for any path.
func TestScanPerRequest_NoFP_JSONReflector(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"requested":"` + r.URL.Path + `","note":"echo"}`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a JSON echo/catch-all must not be flagged as exposed Firebase config")
}

// TestScanPerRequest_NoFP_StructuredFileAsHTMLDocument isolates the content-type
// gate. A structured Firebase file (.runtimeconfig.json — genuine content is JSON,
// never an HTML *document*) is served as 200 text/html ONLY at its own path, with
// every sibling 404. The body carries the weak "{"/`":` markers but no
// <!DOCTYPE/<html anti-marker, and is long/distinct so the 404 length-ratio
// fingerprint diverges. Because the siblings 404, the same-extension decoy
// disproof cannot fire — so the truncation-proof content-type gate (a JSON file
// coming back as an HTML document is the catch-all/echo shell, not the real file)
// is the SOLE guard that must suppress the finding.
func TestScanPerRequest_NoFP_StructuredFileAsHTMLDocument(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.runtimeconfig.json" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`server config { "apiToken": "reflected", "note": "shell" } ` +
				strings.Repeat("x", 300)))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a .runtimeconfig.json served as an HTML document must be rejected by the content-type gate")
}
