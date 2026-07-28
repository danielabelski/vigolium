package modkit_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestEndpointVolatile_FlagsRoundRobinBackends(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(modtest.RoundRobinHandler(&hits,
		modtest.ApacheDefaultPageRHEL, modtest.ApacheDefaultPageUbuntu))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	assert.True(t, modkit.EndpointVolatile(&modkit.ScanContext{}, rr, client),
		"an endpoint answering the same unmodified request with two different pages must be reported volatile")
}

func TestEndpointVolatile_StableEndpointIsNotVolatile(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(modtest.RoundRobinHandler(&hits, modtest.ApacheDefaultPageRHEL))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	assert.False(t, modkit.EndpointVolatile(&modkit.ScanContext{}, rr, client),
		"a deterministic endpoint must never be reported volatile — that would suppress genuine findings")
}

// TestEndpointVolatile_StatusFlapIsVolatile covers the flap that changes status
// rather than body: an endpoint alternating 200/503 is volatile too.
func TestEndpointVolatile_StatusFlapIsVolatile(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt64(&hits, 1)%2 == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write([]byte(modtest.ApacheDefaultPageRHEL))
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	assert.True(t, modkit.EndpointVolatile(&modkit.ScanContext{}, rr, client))
}

// TestEndpointVolatile_MemoizesPerRecord asserts the verdict is sampled once per
// observed record: the gate is called at every candidate a scan raises (and by
// every module processing that record), so re-sampling on each call would
// multiply a scan's traffic.
func TestEndpointVolatile_MemoizesPerRecord(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(modtest.RoundRobinHandler(&hits,
		modtest.ApacheDefaultPageRHEL, modtest.ApacheDefaultPageUbuntu))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")
	sc := &modkit.ScanContext{}

	require.True(t, modkit.EndpointVolatile(sc, rr, client))
	after := atomic.LoadInt64(&hits)
	require.LessOrEqual(t, after, int64(modkit.EndpointStabilitySamples),
		"the first call must send at most EndpointStabilitySamples requests")

	for i := 0; i < 5; i++ {
		assert.True(t, modkit.EndpointVolatile(sc, rr, client))
	}
	assert.Equal(t, after, atomic.LoadInt64(&hits), "repeat calls must be served from the memoized verdict")
}

// TestEndpointVolatile_FailsOpen covers the deliberate fail-open contract: a dead
// host, a nil context, or a nil client must read as "not proven volatile" so a
// transient failure never suppresses a genuine finding.
func TestEndpointVolatile_FailsOpen(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(modtest.RoundRobinHandler(&hits, modtest.ApacheDefaultPageRHEL))
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")
	srv.Close() // no listener: every sample fails at the transport layer

	assert.False(t, modkit.EndpointVolatile(&modkit.ScanContext{}, rr, client))
	assert.False(t, modkit.EndpointVolatile(&modkit.ScanContext{}, nil, client))
	assert.False(t, modkit.EndpointVolatile(&modkit.ScanContext{}, rr, nil))
	assert.False(t, modkit.EndpointVolatile(nil, nil, nil))
}
