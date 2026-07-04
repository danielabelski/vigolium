package graphql_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "graphql-scan"
	ModuleName  = "GraphQL Security Scanner"
	ModuleShort = "Tests GraphQL endpoints for introspection, injection, and batching vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** On a confirmed live GraphQL endpoint, this scanner multi-round-checks introspection (and auto-exercises the schema), error- and boolean-based SQL injection, an exposed IDE (GraphiQL/Playground/Altair), uncapped batching, IDOR/BOLA on predictable ids, reflected error XSS, and a missing depth/complexity limit.

**How it's exploited:** Introspection and consoles map and query the API; injectable arguments read data; batching bypasses rate limits to brute-force credentials; predictable ids expose other records; reflected errors run in the browser.

**Fix:** Disable introspection and consoles in production, parameterize resolvers, cap batching, enforce depth/complexity limits, scope objects to the caller, and return generic HTML-encoded errors.`

	ModuleConfirmation = "Confirmed across multiple independent rounds on a live GraphQL endpoint: introspection/operations execute, SQL payloads produce database errors or boolean-differential responses, a console renders, an uncapped batch executes, sequential ids return distinct objects, or error input reflects unescaped"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"graphql", "injection", "info-disclosure", "idor", "bola", "xss", "dos", "batching", "console", "moderate"}
)
