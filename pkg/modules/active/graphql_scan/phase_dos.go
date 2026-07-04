package graphql_scan

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/graphqlx"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// dosProbeDepth is the nesting depth used to observe whether a depth/complexity
// limit is enforced. Deliberately moderate: it is a configuration probe, not an
// amplification attack (single query, no aliasing, no large list args).
const dosProbeDepth = 10

// depthLimitMarkers are substrings that indicate the server rejected the nested
// query with a depth/complexity/cost limit — i.e. protection IS in place.
var depthLimitMarkers = []string{
	"maximum operation depth", "query depth", "maximum depth", "depth limit",
	"too deep", "query is too complex", "too complex", "complexity",
	"maximum cost", "cost limit", "query exceeds", "exceeds maximum",
}

func hasDepthLimitMarker(body string) bool {
	lower := strings.ToLower(body)
	for _, mk := range depthLimitMarkers {
		if strings.Contains(lower, mk) {
			return true
		}
	}
	return false
}

// phaseDoS checks whether the endpoint enforces a query-depth / complexity limit.
// It is gated behind DeepScan because, while the probe itself is bounded, depth
// testing is heavier than the default surface. A finding is raised only when a
// depth-10 nested query is executed (returns a data envelope) without any
// depth/complexity-limit error, confirmed across independent rounds.
func (m *Module) phaseDoS(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpointPath string,
	schema *graphqlx.Schema,
	target string,
) *output.ResultEvent {
	if schema == nil {
		return nil
	}
	probe, ok := schema.DepthProbe(dosProbeDepth)
	if !ok {
		return nil // no self-referential cycle to nest through
	}
	body := graphqlx.QueryBody(probe)

	unlimited := confirmRounds(defaultConfirmRounds, func() (bool, error) {
		r, err := m.send(ctx, httpClient, "POST", endpointPath, "application/json", body)
		if err != nil {
			return false, err
		}
		if r.blocked {
			return false, nil
		}
		// Server executed the deep query (data envelope) and did NOT reject it
		// with a depth/complexity limit → no limit enforced.
		if hasDepthLimitMarker(r.body) {
			return false, nil
		}
		return strings.Contains(r.body, `"data"`), nil
	})
	if !unlimited {
		return nil
	}

	return &output.ResultEvent{
		URL:     target,
		Matched: target + endpointPath,
		ExtractedResults: []string{
			fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
			fmt.Sprintf("Executed a depth-%d nested query with no depth/complexity limit", dosProbeDepth),
		},
		Info: output.Info{
			Name: "GraphQL Query Depth Not Limited",
			Description: fmt.Sprintf(
				"The GraphQL endpoint executed a depth-%d nested query without enforcing a depth or "+
					"complexity limit. Unbounded query nesting through circular relationships lets an "+
					"attacker craft expensive queries that exhaust CPU and memory (denial of service). "+
					"Enforce a maximum query depth and a query-complexity/cost limit.",
				dosProbeDepth),
			Severity:   severity.Low,
			Confidence: severity.Tentative,
		},
	}
}
