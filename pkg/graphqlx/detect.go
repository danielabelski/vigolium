package graphqlx

import "bytes"

// TypenameQuery is the minimal probe used to confirm an endpoint speaks GraphQL.
const TypenameQuery = `{"query":"{ __typename }"}`

// LooksLikeGraphQLResponse reports whether a response body is plausibly from a
// GraphQL backend: it must be JSON-shaped and carry a GraphQL envelope key
// ("data" or a spec-shaped "errors" array), not merely contain the word
// graphql. This is a necessary (not sufficient) signal — callers combine it
// with a positive probe (e.g. __typename echoed back).
func LooksLikeGraphQLResponse(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return false
	}
	return containsAny(trimmed, `"data"`, `"errors"`)
}

// ConfirmsTypename reports whether a probe response actually reflects the
// __typename query result, i.e. a real GraphQL engine answered. A generic 200
// JSON page or GraphiQL HTML will not carry both the data envelope and the
// echoed __typename key.
func ConfirmsTypename(body []byte) bool {
	return containsAll(body, `"data"`, `"__typename"`)
}

func containsAll(body []byte, subs ...string) bool {
	for _, s := range subs {
		if !bytes.Contains(body, []byte(s)) {
			return false
		}
	}
	return true
}

func containsAny(body []byte, subs ...string) bool {
	for _, s := range subs {
		if bytes.Contains(body, []byte(s)) {
			return true
		}
	}
	return false
}
