package path_relative_stylesheet

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

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

const prssiPage = `<html><head><link rel="stylesheet" href="theme.css"></head><body>Account overview page content here</body></html>`

// prssiServer serves the page at /app/page and any path-info descendant, and 404s a
// nonexistent sibling. nosniff toggles the exploitability gate.
func prssiServer(nosniff bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/app/page" || strings.HasPrefix(p, "/app/page/") {
			w.Header().Set("Content-Type", "text/html")
			if nosniff {
				w.Header().Set("X-Content-Type-Options", "nosniff")
			}
			_, _ = w.Write([]byte(prssiPage))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
}

func TestDetectsPRSSI(t *testing.T) {
	t.Parallel()
	srv := prssiServer(false)
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/app/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a path-relative stylesheet + path-info + no nosniff must fire")
	assert.Equal(t, ModuleName, res[0].Info.Name)
}

func TestNosniffSuppresses(t *testing.T) {
	t.Parallel()
	srv := prssiServer(true)
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/app/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "X-Content-Type-Options: nosniff must suppress the finding")
}

// A universal catch-all (every path returns the page) must be rejected, since the
// control sibling also returns the page.
func TestCatchAllSuppresses(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(prssiPage))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/app/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a universal catch-all must not be reported as PRSSI")
}

func TestPathRelativeStylesheetDetection(t *testing.T) {
	t.Parallel()
	assert.True(t, hasPathRelativeStylesheet(`<link rel="stylesheet" href="theme.css">`))
	assert.True(t, hasPathRelativeStylesheet(`<link href='css/app.css' rel='stylesheet'>`))
	assert.False(t, hasPathRelativeStylesheet(`<link rel="stylesheet" href="/static/theme.css">`), "root-relative is safe")
	assert.False(t, hasPathRelativeStylesheet(`<link rel="stylesheet" href="https://cdn.example.com/a.css">`), "absolute is safe")
	assert.False(t, hasPathRelativeStylesheet(`<link rel="stylesheet" href="//cdn.example.com/a.css">`), "protocol-relative is safe")
	assert.False(t, hasPathRelativeStylesheet(`<link rel="icon" href="favicon.ico">`), "non-stylesheet link ignored")
}
