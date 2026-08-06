package dependent_response

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

// TestUserAgentDependent: the server serves a large page to a crawler UA and a small
// page otherwise, stably. The User-Agent dependence is reported; Referer is not.
func TestUserAgentDependent(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("a", 5000)
	small := strings.Repeat("b", 400)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("User-Agent"), "Googlebot") {
			_, _ = io.WriteString(w, big)
			return
		}
		_, _ = io.WriteString(w, small)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "only the User-Agent dimension should fire")
	assert.Contains(t, res[0].Info.Description, "User-Agent")
}

// TestNoDependence: a fixed response regardless of headers yields nothing.
func TestNoDependence(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 1000))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a header-independent response must not fire")
}

// TestVolatileNotReported: a response whose size flaps per request is unstable, so
// the A-vs-B difference is rejected as dynamic-content noise.
func TestVolatileNotReported(t *testing.T) {
	t.Parallel()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Alternate size every request regardless of headers.
		if atomic.AddInt64(&n, 1)%2 == 0 {
			_, _ = io.WriteString(w, strings.Repeat("a", 5000))
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("b", 400))
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/page"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a volatile endpoint must not yield a dependent-response finding")
}
