package graphql_scan

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/graphqlx"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Boolean-based SQLi probe values. All three share the same base so the only
// difference is the injected boolean, isolating the query-logic change from the
// legitimate value change.
const (
	sqliBase        = "vigoliumzz"
	sqliTrueSuffix  = "' OR '1'='1"
	sqliFalseSuffix = "' AND '1'='2"
)

// maxBoolSQLiCandidates caps how many string-arg fields are probed per host.
const maxBoolSQLiCandidates = 5

// phaseBooleanSQLi looks for boolean-based SQL injection through GraphQL string
// arguments, complementing the error-based detector. It sends a benign control,
// an always-true payload, and an always-false payload sharing one base value;
// the classic signature is FALSE matching the inert control while TRUE diverges
// from it. Bodies are compared with the shared token-ratio similarity
// (dynamic-content robust), and the full differential must reproduce across
// independent rounds — rejecting fields whose responses merely vary with the
// literal value or over time.
func (m *Module) phaseBooleanSQLi(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpointPath string,
	schema *graphqlx.Schema,
	target string,
) *output.ResultEvent {
	if schema == nil {
		return nil
	}

	type candidate struct {
		field *graphqlx.Field
		arg   string
	}
	var candidates []candidate
	for _, f := range schema.QueryFields() {
		for _, a := range f.Args {
			if a == nil {
				continue
			}
			if n := a.Type.Named(); n == "String" || n == "ID" {
				candidates = append(candidates, candidate{field: f, arg: a.Name})
			}
		}
	}
	if len(candidates) > maxBoolSQLiCandidates {
		candidates = candidates[:maxBoolSQLiCandidates]
	}

	for _, c := range candidates {
		send := func(val string) (string, bool) {
			q, ok := schema.RenderProbe(c.field, c.arg, graphqlx.QuoteString(val), 0)
			if !ok {
				return "", false
			}
			r, err := m.send(ctx, httpClient, "POST", endpointPath, "application/json", graphqlx.QueryBody(q))
			if err != nil || r.blocked {
				return "", false
			}
			if !graphqlx.LooksLikeGraphQLResponse([]byte(r.body)) {
				return "", false
			}
			return r.body, true
		}

		booleanDiff := func() (bool, error) {
			ctrlBody, ok := send(sqliBase)
			if !ok {
				return false, nil
			}
			trueVal := sqliBase + sqliTrueSuffix
			trueBody, ok := send(trueVal)
			if !ok {
				return false, nil
			}
			falseVal := sqliBase + sqliFalseSuffix
			falseBody, ok := send(falseVal)
			if !ok {
				return false, nil
			}
			nc := modkit.NormalizeForRatio(ctrlBody, sqliBase)
			nt := modkit.NormalizeForRatio(trueBody, trueVal)
			nf := modkit.NormalizeForRatio(falseBody, falseVal)
			// Classic boolean-blind signature: the always-false condition matches
			// the inert control (both select nothing extra) while the always-true
			// condition diverges from it.
			return modkit.BodiesSimilar(nf, nc) && !modkit.BodiesSimilar(nt, nc), nil
		}

		if !confirmRounds(defaultConfirmRounds, booleanDiff) {
			continue
		}

		return &output.ResultEvent{
			URL:     target,
			Matched: target + endpointPath,
			ExtractedResults: []string{
				fmt.Sprintf("GraphQL endpoint: %s", endpointPath),
				fmt.Sprintf("Vulnerable field: %s(%s:)", c.field.Name, c.arg),
				fmt.Sprintf("Boolean payloads: %q vs %q", sqliTrueSuffix, sqliFalseSuffix),
			},
			Info: output.Info{
				Name: "Boolean-Based SQL Injection via GraphQL",
				Description: fmt.Sprintf(
					"GraphQL field '%s' argument '%s' is vulnerable to boolean-based SQL injection: an "+
						"always-false condition matched a benign control while an always-true condition "+
						"(sharing the same base value) diverged from it, so the injected boolean altered "+
						"query results. Use parameterized queries in the resolver.",
					c.field.Name, c.arg),
				Severity:   severity.High,
				Confidence: severity.Firm,
			},
		}
	}
	return nil
}
