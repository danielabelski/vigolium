package rails_sensitive_files

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// databaseYML is a leaked Rails database config carrying the markers
// (adapter:/database:) the module requires.
const databaseYML = `default: &default
  adapter: postgresql
  encoding: unicode
  database: myapp_production
  username: admin
  password: s3cret
`

// TestScanPerRequest_DetectsDatabaseConfig serves /config/database.yml with the
// telltale markers, while returning a distinct 404 elsewhere.
func TestScanPerRequest_DetectsDatabaseConfig(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config/database.yml" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(databaseYML))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found body contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when database.yml is exposed")
}

// TestScanPerRequest_NoFalsePositive ensures a host that 404s every probe path
// yields no findings.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>Not Found</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host without exposed Rails files must not yield findings")
}

// TestScanPerRequest_BlankLocalSecretNoFalsePositive reproduces the catch-all FP
// where /tmp/local_secret.txt returns a blank 200 while unknown paths return a
// distinct non-empty 404. The markerless local-secret case only had an upper
// length bound, so an empty body would slip through and be reported as a leaked
// secret. The hex-token structural check must drop it.
func TestScanPerRequest_BlankLocalSecretNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tmp/local_secret.txt" {
			w.WriteHeader(http.StatusOK) // blank body, Content-Length: 0
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found body contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a blank-body 200 on /tmp/local_secret.txt must not be reported as a leaked secret")
}

// TestScanPerRequest_DetectsLocalSecret confirms the structural fix still
// reports a genuine hex secret_key_base leaked at /tmp/local_secret.txt.
func TestScanPerRequest_DetectsLocalSecret(t *testing.T) {
	t.Parallel()
	secret := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tmp/local_secret.txt" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(secret + "\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("distinct not found body contents here"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "home")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when a hex secret_key_base is exposed")
}

// TestScanPerRequest_CatchAllHTMLNoFalsePositive reproduces the universal
// catch-all / echo-server false positive. The host answers EVERY path with a
// 200 text/html fragment that reflects the requested path and carries weak
// marker words ("gem "/"source" for the Gemfile) in a truncated TAIL (no
// leading <!DOCTYPE / <html>, so the anti-markers are gone; the reflected path
// keeps each body's hash/length distinct so the 404 fingerprint never matches).
// Only the content-type discipline (text/html is never a Rails config file) can
// drop it. Without that guard /Gemfile would forge a "source"/"gem " match.
func TestScanPerRequest_CatchAllHTMLNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Catch-all: 200 + text/html + reflected path + weak markers, for ANY path.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("you asked for " + r.URL.Path + " -- gem source adapter: database:"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html><body>Welcome to the online store front page</body></html>")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an HTML catch-all reflecting weak markers must not forge a Rails-file finding")
}

// TestCanProcess validates the host-liveness gate.
func TestCanProcess(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.com/")
	assert.False(t, New().CanProcess(rr))
	assert.True(t, New().CanProcess(modtest.Response(rr, "text/html", "ok")))
}
