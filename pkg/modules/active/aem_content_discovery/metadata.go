package aem_content_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-content-discovery"
	ModuleName  = "AEM Repository Content Discovery"
	ModuleShort = "Routing-aware JCR repository enumeration: walks the AEM content tree via Sling selectors (DefaultGetServlet .1.json) and QueryBuilder predicates, harvesting config secrets, user accounts, writable nodes, and deployment packages"
)

var (
	ModuleDesc = `**What it means:** AEM serves the JCR repository as data through Sling's DefaultGetServlet and QueryBuilder. Where the dispatcher fails to deny the ` + "`.json`/`.1.json`/`.infinity.json`" + ` selectors (directly or via a bypass), an unauthenticated attacker walks the tree node-by-node and searches it with predicates, exposing config secrets, credential hashes, user accounts, and writable nodes.

**How it's exploited:** ` + "`GET /content.1.json`" + ` returns a node's child names; following them recursively enumerates the tree, and ` + "`hasPermission=jcr:write`" + ` locates anonymously writable nodes.

**Fix:** Deny the JSON selectors at the dispatcher and remove anonymous read/write on ` + "`/home`, `/apps`, `/conf`, `/etc`" + `.`

	ModuleConfirmation = "Confirmed when a JCR read primitive (DefaultGetServlet or QueryBuilder) returns repository nodes that reproduce across rounds and are not a catch-all shell — recursion through discovered child-node names, credential/secret markers, user accounts, or writable-node predicates escalate severity"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aem", "adobe", "info-disclosure", "content-discovery", "jcr", "exposure", "cms", "moderate"}
)
