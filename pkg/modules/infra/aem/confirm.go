package aem

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// MarkerMatch is a predicate over a probe response — the marker a module keyed on.
type MarkerMatch func(ProbeResult) bool

// ReproduceMarker re-fetches path `rounds` times (minimum 2) with the response
// cache bypassed and returns true only if EVERY round still satisfies match. It
// is the static-exposure counterpart to modkit.ConfirmReflection: an AEM servlet
// that genuinely exposes content answers identically on every fetch, whereas a
// one-off marker (a transient error page, a per-request echo, a flapping upstream)
// fails to reproduce. Callers run it after the initial candidate match and the
// soft-404 / catch-all guards, so a reported finding survived several independent
// confirmation rounds.
func ReproduceMarker(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	path string,
	rounds int,
	match MarkerMatch,
) bool {
	if match == nil {
		return false
	}
	if rounds < 2 {
		rounds = 2
	}
	for i := 0; i < rounds; i++ {
		res := Get(ctx, client, path, nil)
		if !res.OK || !match(res) {
			return false
		}
	}
	return true
}
