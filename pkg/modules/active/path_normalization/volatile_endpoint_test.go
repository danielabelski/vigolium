package path_normalization

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// flappingRootHandler answers EVERY request with one of two static default pages
// chosen by a round robin — a parked host fronted by a load balancer with
// mismatched backends, and nothing else. Not one byte of the response depends on
// the path, so no path-normalization inconsistency exists to find.
func flappingRootHandler(hits *int64) http.HandlerFunc {
	return modtest.RoundRobinHandler(hits, modtest.ApacheDefaultPageRHEL, modtest.ApacheDefaultPageUbuntu)
}

// TestScanPerRequest_NoFalsePositiveOnRoundRobinBackends is the end-to-end guard
// for the reported false positive: parked hosts whose load balancer round-robins
// between a Red Hat and an Ubuntu Apache default page were reported as
// path-normalization bypasses at "/". The differential oracle compares the
// backed-off path against a baseline captured once at the top of the scan, so on
// such a host "the traversal reached a materially different resource than the
// clean path" is satisfied by the load balancer alone.
func TestScanPerRequest_NoFalsePositiveOnRoundRobinBackends(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(flappingRootHandler(&hits))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, res, "a parked host serving one of two static default pages per round robin normalizes nothing")
}

// TestScanPerRequest_VolatileEndpointSuppressesFinding isolates the gate: the
// genuine normalization surface from normalizationHandler is reported as before,
// and the identical surface is dropped once the scan has observed the host
// answering the unmodified request two different ways. It also covers the reason
// the module's existing guards could not catch this at "/": the root-resolution
// re-fetch is skipped outright when the scanned path already IS the root, so a
// single baseline sample decides the whole differential oracle.
func TestScanPerRequest_VolatileEndpointSuppressesFinding(t *testing.T) {
	t.Parallel()
	var flapping atomic.Bool
	var hits int64
	inner := normalizationHandler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if flapping.Load() {
			flappingRootHandler(&hits)(w, r)
			return
		}
		inner(w, r)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/app/page")

	// Control: the genuine bypass is still reported through the new gate.
	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "the volatility gate must not suppress a genuine normalization bypass")

	sc := &modkit.ScanContext{}
	flapping.Store(true)
	require.True(t, modkit.EndpointVolatile(sc, rr, client))
	flapping.Store(false)

	res, err = New().ScanPerRequest(rr, client, sc)
	require.NoError(t, err)
	require.Empty(t, res, "a path differential observed on a non-deterministic endpoint is not evidence of a bypass")
}
