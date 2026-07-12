package http

import (
	"net/http"
	"testing"
	"time"

	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
)

// newEdgePacerRequester builds a minimal Requester over the given host limiter,
// enough to exercise maybePaceEdge without a network round-trip.
func newEdgePacerRequester(t *testing.T, lim *hostlimit.HostRateLimiter) *Requester {
	t.Helper()
	return &Requester{
		services:  &services.Services{HostLimiter: lim},
		edgePacer: &edgePacer{},
	}
}

// wafArmLimiter returns a WafAutoArm limiter plus a slice its pre-arm notices land in.
func wafArmLimiter(t *testing.T) (*hostlimit.HostRateLimiter, *[]hostlimit.PreArmNotice) {
	t.Helper()
	lim := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost: 16, WafAutoArm: true, EvictInterval: time.Hour,
	})
	t.Cleanup(func() { _ = lim.Close() })
	var notices []hostlimit.PreArmNotice
	lim.SetPreArmNotifier(func(n hostlimit.PreArmNotice) { notices = append(notices, n) })
	return lim, &notices
}

func TestMaybePaceEdge_FiresOncePerEdgeHost(t *testing.T) {
	lim, notices := wafArmLimiter(t)
	r := newEdgePacerRequester(t, lim)

	// A clean 200 fronted by CloudFront must pre-arm and notify exactly once.
	c1 := buildChain(t, 200, http.Header{"X-Amz-Cf-Id": {"abc123"}}, "ok")
	r.maybePaceEdge("login.example.com", c1, false)
	c1.Close()

	// A second edge response on the same host must not re-notify (claimed once).
	c2 := buildChain(t, 200, http.Header{"X-Amz-Cf-Id": {"def456"}}, "ok")
	r.maybePaceEdge("login.example.com", c2, false)
	c2.Close()

	if len(*notices) != 1 {
		t.Fatalf("want exactly 1 pacing notice per host, got %d", len(*notices))
	}
	if n := (*notices)[0]; n.Host != "login.example.com" || n.Vendor != "cloudfront" || n.From != 16 || n.Start != 4 {
		t.Fatalf("notice = %+v, want host=login.example.com vendor=cloudfront from=16 start=4", n)
	}
}

func TestMaybePaceEdge_PlainOriginNotPaced(t *testing.T) {
	lim, notices := wafArmLimiter(t)
	r := newEdgePacerRequester(t, lim)

	c := buildChain(t, 200, http.Header{"Server": {"nginx/1.25.3"}}, "ok")
	r.maybePaceEdge("origin.example.com", c, false)
	c.Close()

	if len(*notices) != 0 {
		t.Fatalf("plain origin must not be paced, got %d notices", len(*notices))
	}
}

func TestMaybePaceEdge_BlockedHostClaimedWithoutNotice(t *testing.T) {
	lim, notices := wafArmLimiter(t)
	r := newEdgePacerRequester(t, lim)

	// A block response is handled by the reactive path; the pacer claims the host so
	// it stops fingerprinting, but must NOT fire the (proactive) pacing notice.
	c1 := buildChain(t, 403, http.Header{"Server": {"cloudflare"}}, "blocked")
	r.maybePaceEdge("blocked.example.com", c1, true)
	c1.Close()
	if len(*notices) != 0 {
		t.Fatalf("blocked host must not fire a pacing notice, got %d", len(*notices))
	}

	// A later clean edge response on the same (already-claimed) host stays silent.
	c2 := buildChain(t, 200, http.Header{"Server": {"cloudflare"}, "Cf-Ray": {"7d9-SIN"}}, "ok")
	r.maybePaceEdge("blocked.example.com", c2, false)
	c2.Close()
	if len(*notices) != 0 {
		t.Fatalf("already-claimed host must stay silent, got %d", len(*notices))
	}
}

func TestMaybePaceEdge_StaticLimiterNoOp(t *testing.T) {
	// Without WafAutoArm/Adaptive the limiter is static and not PreArmable, so the
	// pacer must short-circuit and never notify — a non-WAF scan is unaffected.
	lim := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost: 16, EvictInterval: time.Hour,
	})
	t.Cleanup(func() { _ = lim.Close() })
	var notices []hostlimit.PreArmNotice
	lim.SetPreArmNotifier(func(n hostlimit.PreArmNotice) { notices = append(notices, n) })
	r := newEdgePacerRequester(t, lim)

	c := buildChain(t, 200, http.Header{"X-Amz-Cf-Id": {"abc123"}}, "ok")
	r.maybePaceEdge("login.example.com", c, false)
	c.Close()

	if len(notices) != 0 {
		t.Fatalf("static limiter must not pace, got %d notices", len(notices))
	}
}
