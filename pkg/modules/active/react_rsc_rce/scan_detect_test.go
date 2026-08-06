package react_rsc_rce

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

// nextBody is an observed response that carries a Next.js marker so the fingerprint
// gate admits the host.
const nextBody = `<html><head></head><body><div id="__next"></div><script src="/_next/static/chunks/main.js"></script></body></html>`

// vulnerableServer 500s with an error digest only for the crafted colon-delimited
// reference; the benign control ($undefined) decodes cleanly.
func vulnerableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "$1:a:a") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`2:E{"digest":"3268453970"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("0:{}"))
			return
		}
		_, _ = w.Write([]byte(nextBody))
	}))
}

func drive(t *testing.T, srv *httptest.Server) []*output.ResultEvent {
	t.Helper()
	rr := modtest.RequestMethod(t, "GET", srv.URL+"/", "")
	rr = modtest.Response(rr, "text/html", nextBody)
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	return res
}

func TestScanPerRequest_DetectsRSCDecoderCrash(t *testing.T) {
	t.Parallel()
	srv := vulnerableServer()
	defer srv.Close()

	res := drive(t, srv)
	require.NotEmpty(t, res, "a Next.js host that 500s with an error digest for the crafted reference (but not the control) must fire")
	assert.Equal(t, ModuleName, res[0].Info.Name)
}

// A host that 500s with a digest for EVERY server-action call (including the benign
// control) must not be reported — the crash is not attributable to our payload.
func TestScanPerRequest_AlwaysErroringNotReported(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`2:E{"digest":"always"}`))
			return
		}
		_, _ = w.Write([]byte(nextBody))
	}))
	defer srv.Close()

	assert.Empty(t, drive(t, srv), "an endpoint that 500s+digest for the control too must not fire")
}

// A non-Next.js host must be skipped by the fingerprint gate even if it 500s with a
// digest-shaped body.
func TestScanPerRequest_NonNextSkipped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`E{"digest":"x"} Error`))
			return
		}
		_, _ = w.Write([]byte("<html>plain app, no framework markers</html>"))
	}))
	defer srv.Close()

	rr := modtest.RequestMethod(t, "GET", srv.URL+"/", "")
	rr = modtest.Response(rr, "text/html", "<html>plain app, no framework markers</html>")
	res, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-Next.js host must be skipped")
}
