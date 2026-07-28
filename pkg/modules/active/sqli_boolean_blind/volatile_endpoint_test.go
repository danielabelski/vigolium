package sqli_boolean_blind

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// poolHandler serves the two default pages either as a genuine boolean sink (the
// injected condition decides which page renders) or as a mismatched backend pool
// (a round robin decides, and the request is ignored entirely). flapping selects
// which, so one test can compare the module's verdict on the two surfaces while
// holding the response bodies — and therefore every similarity/size comparison
// the module makes — exactly constant.
func poolHandler(flapping *atomic.Bool, hits *int64) http.HandlerFunc {
	pool := modtest.RoundRobinHandler(hits, modtest.ApacheDefaultPageRHEL, modtest.ApacheDefaultPageUbuntu)
	return func(w http.ResponseWriter, r *http.Request) {
		if flapping.Load() {
			pool(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		if evalBool(r.URL.Query().Get("id")) == truePage {
			_, _ = fmt.Fprint(w, modtest.ApacheDefaultPageRHEL)
			return
		}
		_, _ = fmt.Fprint(w, modtest.ApacheDefaultPageUbuntu)
	}
}

// TestScanPerRequest_VolatileEndpointSuppressesFinding is the regression guard
// for the reported false positive: four parked hosts, each with no application
// behind it, reported "certain" High boolean-blind SQLi because their load
// balancer round-robined between two mismatched backends (a Red Hat and an
// Ubuntu Apache default page). Every pairwise check the module runs — TRUE vs
// FALSE, each vs the baseline, the TRUE/FALSE retry stability, the
// baseline-drift re-fetch, the multi-round randomized confirmation — is a coin
// flip on such a host, so across a scan's payload × insertion-point fan-out some
// sequence of flips eventually lines up. No amount of pairwise re-comparison
// rejects that; the endpoint has to be proven to be a function of the request.
//
// The test holds the response bodies constant and varies ONLY determinism, so
// the two halves isolate the gate: a genuine boolean sink serving these exact
// pages is still reported, and the same sink is dropped once the scan has
// observed the host answering the unmodified request two different ways.
func TestScanPerRequest_VolatileEndpointSuppressesFinding(t *testing.T) {
	t.Parallel()
	var flapping atomic.Bool
	var hits int64
	srv := httptest.NewServer(poolHandler(&flapping, &hits))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?id=1")

	// Control: on a deterministic endpoint these two pages are a real oracle and
	// the finding must survive the new gate.
	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "the volatility gate must not suppress a genuine boolean sink")

	// Now let the scan observe the host flapping on the UNMODIFIED request — what
	// the real parked pool did — then re-scan the identical sink. The differential
	// is found exactly as before; only the determinism verdict differs.
	sc := &modkit.ScanContext{}
	flapping.Store(true)
	require.True(t, modkit.EndpointVolatile(sc, rr, client))
	flapping.Store(false)

	res, err = New().ScanPerRequest(rr, client, sc)
	require.NoError(t, err)
	require.Empty(t, res, "a differential observed on a non-deterministic endpoint is not evidence of SQL injection")
}

// TestScanPerRequest_NoFalsePositiveOnRoundRobinBackends drives the reported
// surface end to end: a parked host with no application at all, serving one of
// two static default pages per round robin. Nothing here is injectable, so the
// module must stay silent whichever of its guards gets there first.
func TestScanPerRequest_NoFalsePositiveOnRoundRobinBackends(t *testing.T) {
	t.Parallel()
	var flapping atomic.Bool
	flapping.Store(true)
	var hits int64
	srv := httptest.NewServer(poolHandler(&flapping, &hits))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/?id=1")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, res, "a parked host round-robining between two static default pages has no SQL sink to inject into")
}
