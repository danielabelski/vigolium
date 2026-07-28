package modkit

import (
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const (
	// EndpointStabilitySamples is how many times the UNMODIFIED request is
	// replayed to decide whether the endpoint answers deterministically.
	//
	// A backend pool is a coin flip, so a miss is (1/backends)^(samples-1) times
	// the backend count: three samples leave a 1-in-4 miss on a two-backend pool,
	// which is far too coarse to gate a High finding — re-scanning the four hosts
	// that motivated this suppressed three and let the fourth through, exactly as
	// that rate predicts. Eight samples take the miss to under 1%, and cost
	// almost nothing in practice: sampling stops at the FIRST divergence (so a
	// flapping host usually pays two requests), the full run is only paid on the
	// deterministic hosts that are about to report a real finding, and the verdict
	// is memoized per record across every candidate and module.
	EndpointStabilitySamples = 8

	// stabilityCacheSize bounds the per-scan endpoint-volatility verdict cache.
	stabilityCacheSize = 512
)

func (sc *ScanContext) getStabilityCache() *lru.Cache[string, bool] {
	sc.stabilityOnce.Do(func() {
		sc.stabilityCache, _ = lru.New[string, bool](stabilityCacheSize)
	})
	return sc.stabilityCache
}

// EndpointVolatile reports whether the endpoint answers the SAME unmodified
// request with materially different responses across repeated fetches.
//
// It exists because every body-differential oracle — boolean-blind SQLi/NoSQLi,
// path-normalization's "the traversal reached a different resource than the
// clean path", cross-ID comparisons — implicitly assumes the endpoint is a
// function of the request. A host whose load balancer round-robins between
// mismatched backends breaks that assumption outright: the observed false
// positive was a pool of parked hosts where an identical `GET /` returned either
// a 5.9 KB "Red Hat Enterprise Linux Test Page" or an 11.3 KB "Apache2 Ubuntu
// Default Page" at random. Every pairwise guard those modules run — TRUE vs
// FALSE, probe vs baseline, and each single-retry stability check — is then a
// coin flip, and across a scan's payload × insertion-point fan-out some sequence
// of flips inevitably lines up into a "confirmed" High finding.
//
// No amount of pairwise re-comparison fixes that; the endpoint has to be proven
// deterministic once, from samples of the unmodified request alone. Callers
// should invoke this as a LAST gate, at the moment they are about to report,
// rather than up front: candidates are rare, the verdict is memoized per record
// (and shared across modules processing that record), so a scan pays the extra
// round-trips only on hosts that actually produced something.
//
// It fails OPEN — a nil context/client, a build error, or any transport failure
// returns false ("not proven volatile") — so a flaky probe never suppresses a
// genuine finding. Replays carry the observed request verbatim, including its
// method and body; callers on non-idempotent requests inherit that, which is the
// same trade the differential modules already make when they replay a request
// dozens of times with mutated values.
func EndpointVolatile(sc *ScanContext, ctx *httpmsg.HttpRequestResponse, client *http.Requester) bool {
	if ctx == nil || ctx.Request() == nil || client == nil {
		return false
	}
	if sc == nil {
		return sampleVolatile(ctx, client)
	}

	key := ctx.Request().ID()
	cache := sc.getStabilityCache()
	if v, ok := cache.Get(key); ok {
		return v
	}
	res, _, _ := sc.stabilityFlight.Do(key, func() (interface{}, error) {
		if v, ok := cache.Get(key); ok {
			return v, nil
		}
		v := sampleVolatile(ctx, client)
		cache.Add(key, v)
		return v, nil
	})
	return res.(bool)
}

// sampleVolatile replays the observed request EndpointStabilitySamples times and
// reports whether any sample disagrees with the first on status or page identity.
// Comparing every sample against the first is enough: a pool that answered the
// first request differs from at least one later sample exactly when the pool is
// not serving one page.
//
// The request is parsed once and replayed (fetchResponseBodyParsed treats it as
// immutable), and only the first body's ratio signature is built — the later
// samples are compared against it with BodiesSimilarSig, so no sample pays for
// the whole-body SHA-256 that NewResponseSignature would compute and that the
// similarity comparison never reads.
func sampleVolatile(ctx *httpmsg.HttpRequestResponse, client *http.Requester) bool {
	req := httpmsg.NewRequestResponseRaw(ctx.Request().Raw(), ctx.Service())

	var firstStatus int
	var firstSig ResponseSignature

	for i := 0; i < EndpointStabilitySamples; i++ {
		// NoRedirects keeps the comparison on the endpoint's own answer rather than
		// on whatever a redirect chain happens to land on.
		status, body, ok := fetchResponseBodyParsed(client, req, true)
		if !ok {
			return false // transport failure — fail open
		}
		if i == 0 {
			firstStatus, firstSig = status, BodySignature(body)
			continue
		}
		if status != firstStatus || !BodiesSimilarSig(firstSig, body) {
			return true
		}
	}
	return false
}
