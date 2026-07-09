package fastify_hono_probe

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerHost_DetectsFastifySwagger serves a Fastify Swagger doc JSON at
// /documentation/json, which the host probe should flag.
func TestScanPerHost_DetectsFastifySwagger(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/documentation/json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"swagger":"2.0","openapi":"3.0.0","info":{}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when Fastify Swagger docs are exposed")
}

// TestScanPerHost_DetectsFastifyMetrics serves a Prometheus exposition body at
// the metrics path, which the host probe should flag.
func TestScanPerHost_DetectsFastifyMetrics(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/fastify/metrics" {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("# HELP process_cpu_user_seconds_total Total user CPU time.\n" +
				"# TYPE process_cpu_user_seconds_total counter\n" +
				"process_cpu_user_seconds_total 1.23\n" +
				"nodejs_eventloop_lag_seconds 0.001\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the Fastify metrics endpoint serves Prometheus content")
}

// TestScanPerHost_NoFalsePositive_PathReflectingEcho reproduces the self-reflection
// FP with body truncation: an echo / catch-all handler mirrors the request path
// into a 200 text/html tail for EVERY path (no leading <!DOCTYPE, so the head-keyed
// wildcard soft-404 guard is defeated — each path's head bytes differ). The
// /fastify-overview probe (marker "fastify") would otherwise self-confirm on the
// word reflected straight back from its own path. Stripping the reflected probe
// path before matching must drop it.
func TestScanPerHost_NoFalsePositive_PathReflectingEcho(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// Truncated tail echoing the request path — /fastify-overview reflects the
		// word "fastify" back, and every path's head differs.
		_, _ = w.Write([]byte(`<div id=app data-route="` + r.URL.Path + `">loading</div>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a path-reflecting echo server must not self-confirm the /fastify-overview marker")
}

// TestScanPerHost_DetectsFastifyOverview confirms the reflected-path strip does not
// suppress a genuine hit: a real overview endpoint whose own content (not just the
// reflected path) names fastify is still reported.
func TestScanPerHost_DetectsFastifyOverview(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fastify-overview" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<h1>Application Overview</h1><ul><li>plugin: fastify-swagger</li>` +
				`<li>plugin: fastify-cors</li></ul>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a real fastify-overview endpoint naming fastify in its content must still be reported")
}

// TestScanPerHost_NoFalsePositive returns 404 for all framework paths, so no
// finding should be produced.
func TestScanPerHost_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "missing framework endpoints must not yield a finding")
}

// TestScanPerHost_NoFalsePositive_EmptyShell reproduces the motivating false
// positive: an SPA/CDN gateway that answers EVERY path — including the metrics
// probe — with `200 OK`, `Content-Type: text/html`, and an empty body. The
// status-only metrics matcher used to flag this; the body/content-type gate
// must now reject it.
func TestScanPerHost_NoFalsePositive_EmptyShell(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK) // 200 for every path, empty body
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>app</html>")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an empty 200 catch-all shell must not be flagged as an exposed endpoint")
}

// TestScanPerHost_NoFalsePositive_HTMLShell covers a catch-all that returns a
// non-empty HTML shell for every path (the SPA index). Even though the body is
// non-empty, no probe's content marker is present, so nothing should fire.
func TestScanPerHost_NoFalsePositive_HTMLShell(t *testing.T) {
	t.Parallel()
	const shell = "<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(shell))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", shell)

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an HTML SPA shell returned for every path must not be flagged")
}
