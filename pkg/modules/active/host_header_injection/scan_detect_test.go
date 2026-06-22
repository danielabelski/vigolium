package host_header_injection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// TestScanPerRequest_DetectsHostHeaderInjection drives the real scan method
// against a server that reflects X-Forwarded-Host into the body (the classic
// password-reset-poisoning sink). The module injects its sentinel host and
// should observe it reflected.
func TestScanPerRequest_DetectsHostHeaderInjection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		_, _ = fmt.Fprintf(w, "<html><body>Reset: https://%s/reset?t=abc</body></html>", xfh)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/forgot-password")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a host-header-injection finding when X-Forwarded-Host is reflected")
	// A body-only echo is the weaker sink, so it ships as Tentative.
	assert.Equal(t, severity.Tentative, res[0].Info.Confidence, "a body-only host reflection is Tentative")
}

// TestScanPerRequest_LocationReflectionIsFirm reflects the injected host into the
// Location header (the password-reset-poisoning / cache-poisoning sink). That is
// the strong URL-generation signal, so the confirmed finding ships as Firm.
func TestScanPerRequest_LocationReflectionIsFirm(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Location", "https://"+host+"/dashboard")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/login")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the injected host reflects into Location")
	assert.Equal(t, severity.Firm, res[0].Info.Confidence, "a Location-header host reflection is Firm")
}

// TestScanPerRequest_RedirectURIEchoNoFalsePositive reproduces the CDN/OAuth-login
// false positive: a 302 whose Location targets a fixed, trusted identity provider
// but echoes the request host into the URL-encoded redirect_uri= query parameter.
// The injected host appears in the Location header dump (and reflects for a fresh
// canary), yet never as the redirect authority — the real destination is
// identical with or without the spoofed header. The authority-position guard must
// suppress it instead of reporting a Firm Location reflection.
func TestScanPerRequest_RedirectURIEchoNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		// Authority is always the trusted IdP; the request host only lands inside the
		// URL-encoded redirect_uri= query parameter, never in authority position.
		loc := "https://idp.trusted.example/as/authorization.oauth2?response_type=code&redirect_uri=" +
			url.QueryEscape("https://"+host+"/oauth2/callback")
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/login")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a host echoed only into a redirect_uri= query param (redirect authority unchanged) must not be reported")
}

// TestScanPerRequest_StaticEvilStringNoFalsePositive reproduces the FP the
// fresh-canary confirmation exists to catch: a catch-all that bakes the sentinel
// host string into EVERY response regardless of any header (a cached page, an
// error log, a static link). The reflection does not track a fresh canary, so it
// must be dropped.
func TestScanPerRequest_StaticEvilStringNoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The sentinel host is present unconditionally — never attributable to a header.
		_, _ = fmt.Fprintf(w, "<html><body>known scanner host: %s</body></html>", evilHost)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/forgot-password")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a sentinel string present regardless of the header must not be reported")
}

// TestScanPerRequest_NoFalsePositive ensures a server that ignores the injected
// headers yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>static page, no reflection</body></html>"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/forgot-password")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that ignores host headers must not yield a finding")
}
