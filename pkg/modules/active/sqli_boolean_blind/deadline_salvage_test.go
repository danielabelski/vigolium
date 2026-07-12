package sqli_boolean_blind

import (
	"context"
	"fmt"
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

// paddedIDTarget builds a catalog URL with one vulnerable `id` param followed by
// many inert padding params, so the insertion-point loop is long enough for a
// mid-loop deadline to fall inside it.
func paddedIDTarget(base string) string {
	var b strings.Builder
	b.WriteString(base + "/item?id=1")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&b, "&pad%d=1", i)
	}
	return b.String()
}

// TestScanPerRequestContext_SalvagesFindingOnDeadline is the regression guard for
// the executor's per-module timeout discarding an already-confirmed finding. When
// runCtx is cancelled mid-loop (the executor's soft deadline firing before the
// hard watchdog), the module must return the findings it has already confirmed —
// not the empty result that would be discarded — and must stop early rather than
// grind through every remaining insertion point. The vulnerable `id` query param
// is tested first (points are priority ordered), so it is confirmed before the
// deadline lands amid the padding params.
func TestScanPerRequestContext_SalvagesFindingOnDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancel the run once enough requests have flowed to confirm the `id` param
	// (its full boolean battery is well under 30 requests) but with many padding
	// params still untested — so the cancellation genuinely lands mid-loop.
	const cancelAfter = 40
	var reqCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reqCount.Add(1) == cancelAfter {
			cancel()
		}
		_, _ = fmt.Fprint(w, evalBool(r.URL.Query().Get("id")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, paddedIDTarget(srv.URL))

	res, err := New().ScanPerRequestContext(ctx, rr, client, &modkit.ScanContext{})
	require.NoError(t, err, "a cancelled run must not surface an error")
	require.NotEmpty(t, res, "the confirmed `id` finding must survive mid-loop cancellation, not be discarded")
	assert.Equal(t, "id", res[0].FuzzingParameter)

	// Early return: the cancellation must stop the loop, so far fewer requests fire
	// than a full uncancelled scan of `id` + 20 padding params would.
	if n := reqCount.Load(); n > cancelAfter+30 {
		t.Fatalf("expected the loop to stop shortly after cancellation (~%d requests), got %d — no early return", cancelAfter, n)
	}
}

// TestScanPerRequestContext_FullScanBaseline confirms the same request detects the
// `id` injection when the context is never cancelled, so the salvage test above is
// exercising cancellation rather than a non-detecting setup. It also records that
// an uncancelled scan issues materially more requests than the cancelled one.
func TestScanPerRequestContext_FullScanBaseline(t *testing.T) {
	var reqCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		_, _ = fmt.Fprint(w, evalBool(r.URL.Query().Get("id")))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, paddedIDTarget(srv.URL))

	res, err := New().ScanPerRequestContext(context.Background(), rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected the id injection to be detected on a full (uncancelled) scan")
	assert.Equal(t, "id", res[0].FuzzingParameter)
	if reqCount.Load() <= 40 {
		t.Fatalf("expected a full scan of id + 20 padding params to issue well over 40 requests, got %d", reqCount.Load())
	}
}
