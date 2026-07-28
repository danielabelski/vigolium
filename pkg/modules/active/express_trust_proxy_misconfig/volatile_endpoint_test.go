package express_trust_proxy_misconfig

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_RoundRobinPoolIsNotASizeShift is the regression guard for
// the round-robin backend-pool false positive.
//
// confirmSizeShift describes the no-header and spoofed-IP size bands from TWO
// samples each and reports when they sit clear of one another — "reproducibly
// shifted response size outside natural variance". On a host that round-robins
// between mismatched backends the unmodified request alone has a BIMODAL size
// distribution, so the two bands land on opposite modes (always, against a strict
// round robin) and the header gets the credit. Sweeping such a pool with the full
// module set reproduced this on 5 of 5 runs before the gate was added — the most
// reliable false positive of the whole class.
//
// TestScanPerRequest_IPSizeJitterNoFalsePositive already covers monotonic growth;
// this covers a bimodal endpoint, which that jitter guard does not catch because
// each band is internally consistent.
func TestScanPerRequest_RoundRobinPoolIsNotASizeShift(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(modtest.RoundRobinHandler(&hits,
		modtest.ApacheDefaultPageRHEL, modtest.ApacheDefaultPageUbuntu))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/account")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, res, "a load balancer alternating between two backends is not X-Forwarded-For being trusted")
}
