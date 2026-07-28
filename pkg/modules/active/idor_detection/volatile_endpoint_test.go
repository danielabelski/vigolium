package idor_detection

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// The two renderings a mismatched replica pool returns for the SAME request:
// same template, genuinely different data and length.
const (
	replicaEast = `{"user_id":"12345","email":"dana.whitfield@example.com","plan":"Enterprise",` +
		`"region":"us-east-1","balance":"4182.55","orders":["shipped from the eastern warehouse",` +
		`"shipped from the eastern warehouse","shipped from the eastern warehouse"]}`
	replicaWest = `{"user_id":"12345","account":"rowan.castellanos@example.org","tier":"Starter",` +
		`"zone":"eu-west-3","credit":"97.10","queue":["pending in the european queue"],` +
		`"notice":"replica lagging behind primary; some records may be stale"}`
)

// TestScanPerInsertionPoint_VolatileEndpointSuppressesIDOR is the regression
// guard for the round-robin backend-pool false positive.
//
// The cross-ID noise envelope (ConfirmCrossIDDifferential) measures the
// endpoint's own variation from a couple of same-id refetches. That is the right
// shape, but on a BIMODAL endpoint — two backends rendering the same template
// with different data, which is what a mismatched app pool looks like — every
// refetch lands on the baseline's backend often enough that the envelope reads
// as deterministic, and the neighbour-id difference then looks exactly like
// broken object-level authorization. Sweeping a randomly-flapping pool
// reproduced this on 3 of 3 runs before the gate was added.
//
// The test holds the bodies constant and varies ONLY determinism, so it isolates
// the gate: a real IDOR serving these same bodies is still reported, and the same
// surface is dropped once the scan has observed the host answering the unmodified
// request two different ways.
func TestScanPerInsertionPoint_VolatileEndpointSuppressesIDOR(t *testing.T) {
	t.Parallel()
	var flapping atomic.Bool
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if flapping.Load() {
			// Mismatched backend pool: which replica answers decides the body, and
			// the requested id is ignored entirely. The two replicas render the same
			// template with genuinely different data — different vocabulary and
			// length — because that is what makes a pool bimodal. Two near-identical
			// bodies would (correctly) normalize to one page and not be volatile.
			if atomic.AddInt32(&hits, 1)%2 == 0 {
				_, _ = w.Write([]byte(replicaEast))
				return
			}
			_, _ = w.Write([]byte(replicaWest))
			return
		}
		// Genuine IDOR: every neighbour id returns that object.
		_, _ = w.Write([]byte(objectBody(r.URL.Query().Get("user_id"))))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/api/object?user_id=12345")
	ip := modtest.InsertionPoint(t, rr, "user_id")

	// Control: on a deterministic endpoint this surface is a real IDOR.
	res, err := New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "the volatility gate must not suppress a genuine IDOR")

	// Now let the scan observe the host flapping on the UNMODIFIED request, then
	// re-scan the identical surface.
	sc := &modkit.ScanContext{}
	flapping.Store(true)
	require.True(t, modkit.EndpointVolatile(sc, rr, client))
	flapping.Store(false)

	res, err = New().ScanPerInsertionPoint(rr, ip, client, sc)
	require.NoError(t, err)
	require.Empty(t, res, "a cross-id difference observed on a non-deterministic endpoint is not evidence of broken authorization")
}
