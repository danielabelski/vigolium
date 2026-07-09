package nextjs_chunk_audit

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

// nextShellReferencing returns a Next.js HTML shell that references chunkPath, so
// the module's LooksLikeNextJS gate fires (the "/_next/" marker) and
// ExtractChunkPaths picks the chunk up for fetching.
func nextShellReferencing(chunkPath string) string {
	return `<html><head><script src="` + chunkPath + `"></script></head>` +
		`<body><div id="__next"></div></body></html>`
}

// TestScanPerRequest_CatchAllHTMLChunk_NoFalsePositive reproduces the catch-all /
// echo-server false positive with body truncation: the host answers a chunk path
// with a 200 text/html shell (here a truncated TAIL fragment with no leading
// <!DOCTYPE, echoing the path) that happens to carry a secret-shaped token. A real
// Next.js chunk is JavaScript, never an HTML document, so the fetched "chunk" must
// be rejected on Content-Type before secret/route analysis and yield no finding.
func TestScanPerRequest_CatchAllHTMLChunk_NoFalsePositive(t *testing.T) {
	t.Parallel()
	const chunkPath = "/_next/static/chunks/main-abc123.js"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every path (including the chunk fetch) returns a truncated HTML tail that
		// echoes the request path and embeds a secret-shaped token — the exact shape
		// a weak body scan would flag.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`app boot ` + r.URL.Path +
			` config={apiKey:"AKIAIOSFODNN7EXAMPLE"}</div></body></html>`))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextShellReferencing(chunkPath))

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all HTML shell returned for a chunk path must not forge a secret/intel finding")
}

// TestScanPerRequest_RealJSChunk_DetectsSecret confirms the Content-Type guard does
// not suppress a genuine hit: a real JavaScript chunk (application/javascript) at
// its own path carrying an embedded AWS key is still parsed and reported, while
// other paths 404.
func TestScanPerRequest_RealJSChunk_DetectsSecret(t *testing.T) {
	t.Parallel()
	const chunkPath = "/_next/static/chunks/main-abc123.js"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == chunkPath {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			_, _ = w.Write([]byte(`(()=>{const cfg={awsKey:"AKIAIOSFODNN7EXAMPLE"};return cfg})();`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextShellReferencing(chunkPath))

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a real application/javascript chunk with an embedded key must still be reported")

	var sawSecret bool
	for _, ev := range res {
		if strings.Contains(ev.Info.Name, "Embedded Secret") {
			sawSecret = true
		}
	}
	assert.True(t, sawSecret, "expected an embedded-secret finding for the real JS chunk")
}
