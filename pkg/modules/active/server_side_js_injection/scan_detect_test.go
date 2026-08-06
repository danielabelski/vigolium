package server_side_js_injection

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }

var busyWaitMs = regexp.MustCompile(`b-a<(\d+)`)

// TestPayloadRendering pins the busy-wait substitution and quoting contexts.
func TestPayloadRendering(t *testing.T) {
	t.Parallel()
	require.Len(t, timePayloads, 4)
	for _, p := range timePayloads {
		if !strings.Contains(p.render(6500), "b-a<6500") {
			t.Errorf("%s: slow render should carry the duration: %q", p.context, p.render(6500))
		}
		if !strings.Contains(p.render(0), "b-a<0") {
			t.Errorf("%s: fast render should carry 0: %q", p.context, p.render(0))
		}
	}
	require.Len(t, oastPayloads, 4)
}

// nodeResponse marks the observed response as a Node/JS backend so the tech-stack
// gate admits it.
func nodeResponse(t *testing.T, url string) *httpmsg.HttpRequestResponse {
	rr := modtest.Request(t, url)
	return modtest.Response(rr, "text/html", "<html><head></head><body><script src=/_next/static/x.js></script>__NEXT_DATA__</body></html>")
}

// TestScanPerInsertionPoint_SkipsNonNodeBackend: without a Node signal, the module
// must not probe at all — even a server that would honour the busy-wait delay.
func TestScanPerInsertionPoint_SkipsNonNodeBackend(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mm := busyWaitMs.FindStringSubmatch(r.URL.Query().Get("q")); mm != nil {
			ms, _ := strconv.Atoi(mm[1])
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Observed response carries a PHP marker, not a Node one.
	rr := modtest.Request(t, srv.URL+"/api?q=hello")
	rr = modtest.Response(rr, "text/html", "<html>powered by PHP</html>")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-Node backend must be skipped by the tech-stack gate")
}

// TestScanPerInsertionPoint_NoDelayNoFinding: a Node server that ignores the payload
// (fast for everything) must not fire, and bails after the first slow probe.
func TestScanPerInsertionPoint_NoDelayNoFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rr := nodeResponse(t, srv.URL+"/api?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an endpoint with no evaluable delay must not fire")
}

// TestScanPerInsertionPoint_BusyWaitDelayDetected: a server that honours the busy-wait
// duration (sleeping the requested ms) is reported. Slow because the confirmation
// deliberately requires multi-second, repeated delays.
func TestScanPerInsertionPoint_BusyWaitDelayDetected(t *testing.T) {
	if testing.Short() {
		t.Skip("timing confirmation requires multi-second delays; skipped under -short")
	}
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mm := busyWaitMs.FindStringSubmatch(r.URL.Query().Get("q")); mm != nil {
			ms, _ := strconv.Atoi(mm[1])
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rr := nodeResponse(t, srv.URL+"/api?q=hello")
	ip := modtest.InsertionPoint(t, rr, "q")

	res, err := New().ScanPerInsertionPoint(rr, ip, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a duration-scaled busy-wait delay must be reported")
	assert.Equal(t, ModuleName, res[0].Info.Name)
}
