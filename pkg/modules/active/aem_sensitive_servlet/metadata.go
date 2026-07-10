package aem_sensitive_servlet

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-sensitive-servlet"
	ModuleName  = "AEM Sensitive Servlet Disclosure"
	ModuleShort = "Detects information-disclosure via AEM servlets (QueryBuilder password-hash leak, GQL/DefaultGetServlet dumps, userinfo, loginstatus, truststore) including dispatcher-bypass reachability"
)

var (
	ModuleDesc = `**What it means:** An AEM servlet that discloses repository content, users, or credentials is reachable, directly or via a dispatcher bypass. The worst case is the QueryBuilder servlet leaking rep:password hashes; others expose the JCR tree, user identifiers, the GQL servlet, or the truststore.

**How it's exploited:** An attacker queries /bin/querybuilder.json (often via a .json.css bypass) with type=rep:User to enumerate accounts and dump password hashes, with no authentication.

**Fix:** Deny /bin/querybuilder, the GQL and DefaultGetServlet JSON selectors, userinfo, and /etc/truststore at the dispatcher, and rotate exposed credentials.`

	ModuleConfirmation = "Confirmed when an AEM servlet returns its distinctive disclosure markers (rep:password, jcr:primaryType, success/hits, userID) with a 200 that reproduces across multiple rounds and is not a catch-all shell"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aem", "adobe", "info-disclosure", "exposure", "cms", "light"}
)
