package aem_sensitive_servlet

import (
	"strings"

	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// verdict is what a servlet's eval produces on a confirmed disclosure: the
// finding name, its content-driven severity, and the evidence substrings.
type verdict struct {
	name     string
	severity severity.Severity
	evidence []string
}

// servlet is one sensitive AEM endpoint. eval inspects a probe response and,
// when the disclosure markers are present, returns the verdict (its severity may
// vary with what leaked — e.g. QueryBuilder is Critical when rep:password
// appears, High for user enumeration, Medium when merely reachable). siblingGuard
// enables the same-directory catch-all disproof (skip it for single-file checks).
type servlet struct {
	id           string
	paths        []string
	ref          []string
	baseTags     []string
	siblingGuard bool
	eval         func(res aem.ProbeResult) (verdict, bool)
}

// servlets is the catalog of information-disclosure AEM endpoints.
var servlets = []servlet{
	{
		id: "querybuilder-users",
		paths: []string{
			"/bin/querybuilder.json?p.hits=full&property=rep:authorizableId&type=rep:User",
		},
		ref:          []string{"https://blog.assetnote.io/2021/11/08/aem-vulnerabilities/"},
		baseTags:     []string{"querybuilder", "credential-exposure"},
		siblingGuard: true,
		eval: func(res aem.ProbeResult) (verdict, bool) {
			if res.Status != 200 {
				return verdict{}, false
			}
			b := res.Body
			// Must look like a QueryBuilder JSON result, not an arbitrary page.
			if !strings.Contains(b, `"success":true`) && !strings.Contains(b, "jcr:primaryType") {
				return verdict{}, false
			}
			switch {
			case strings.Contains(b, "rep:password"):
				return verdict{
					name:     "AEM QueryBuilder Password Hash Disclosure",
					severity: severity.Critical,
					evidence: []string{"leaked rep:password hashes via QueryBuilder"},
				}, true
			case aem.HasAny(b, "rep:authorizableId", "rep:principalName"):
				return verdict{
					name:     "AEM QueryBuilder User Enumeration",
					severity: severity.High,
					evidence: []string{"enumerated rep:User accounts via QueryBuilder"},
				}, true
			case aem.HasAll(b, `"success":true`, `"hits":`):
				return verdict{
					name:     "AEM QueryBuilder Servlet Exposed",
					severity: severity.Medium,
					evidence: []string{"QueryBuilder JSON servlet reachable"},
				}, true
			}
			return verdict{}, false
		},
	},
	{
		id: "gql-servlet",
		paths: []string{
			"/bin/wcm/search/gql.json?query=type:base%20limit:..1&pathPrefix=",
		},
		baseTags:     []string{"gql", "search"},
		siblingGuard: true,
		eval: func(res aem.ProbeResult) (verdict, bool) {
			if res.Status != 200 || !aem.HasAll(res.Body, "hits", "path", "excerpt") {
				return verdict{}, false
			}
			return verdict{
				name:     "AEM GQL Search Servlet Exposed",
				severity: severity.Medium,
				evidence: []string{"GQL search servlet returns repository content"},
			}, true
		},
	},
	{
		id: "default-get-servlet",
		paths: []string{
			"/etc.tidy.infinity.json",
			"/apps.tidy.infinity.json",
			"/content.infinity.json",
			"/.json",
		},
		baseTags:     []string{"defaultgetservlet", "jcr"},
		siblingGuard: true,
		eval: func(res aem.ProbeResult) (verdict, bool) {
			if res.Status != 200 {
				return verdict{}, false
			}
			b := res.Body
			// jcr:primaryType is the AEM-specific anchor; require it plus a JSON shape.
			if !strings.Contains(b, "jcr:primaryType") && !strings.Contains(b, "jcr:createdBy") {
				return verdict{}, false
			}
			if !aem.IsJSONContentType(res.ContentType) && !strings.HasPrefix(strings.TrimSpace(b), "{") {
				return verdict{}, false
			}
			if aem.HasAny(b, "rep:password", "rep:privileges") {
				return verdict{
					name:     "AEM Repository Dump - Credential/Privilege Exposure",
					severity: severity.High,
					evidence: []string{"DefaultGetServlet JSON dump exposes rep:password/rep:privileges"},
				}, true
			}
			return verdict{
				name:     "AEM DefaultGetServlet JSON Dump Exposed",
				severity: severity.Medium,
				evidence: []string{"DefaultGetServlet renders repository nodes as JSON"},
			}, true
		},
	},
	{
		id: "aem-secrets",
		paths: []string{
			"/content/dam/formsanddocuments.form.validator.html/home/....children.tidy...infinity..json",
		},
		ref:          []string{"https://speczz.medium.com/aem-hacking-resources"},
		baseTags:     []string{"secrets", "credential-exposure"},
		siblingGuard: false,
		eval: func(res aem.ProbeResult) (verdict, bool) {
			if res.Status != 200 {
				return verdict{}, false
			}
			b := res.Body
			if !aem.HasAll(b, "jcr:uuid", "jcr:createdBy") {
				return verdict{}, false
			}
			if strings.Contains(b, "rep:password") {
				return verdict{
					name:     "AEM Forms Validator Repository Disclosure - Credential Exposure",
					severity: severity.Critical,
					evidence: []string{"forms validator servlet leaks rep:password hashes from /home"},
				}, true
			}
			if strings.Contains(b, "uri") {
				return verdict{
					name:     "AEM Forms Validator Repository Disclosure",
					severity: severity.High,
					evidence: []string{"forms validator servlet dumps /home repository nodes"},
				}, true
			}
			return verdict{}, false
		},
	},
	{
		id: "userinfo-servlet",
		paths: []string{
			"/libs/cq/security/userinfo.json",
		},
		baseTags:     []string{"userinfo", "auth-oracle"},
		siblingGuard: true,
		eval: func(res aem.ProbeResult) (verdict, bool) {
			if res.Status != 200 || !aem.HasAll(res.Body, `"userID":`, `"userName":`) {
				return verdict{}, false
			}
			return verdict{
				name:     "AEM UserInfo Servlet Exposed",
				severity: severity.Low,
				evidence: []string{"userinfo servlet exposes userID/userName (enables brute-force)"},
			}, true
		},
	},
	{
		id: "sling-userinfo",
		paths: []string{
			"/system/sling/info.sessionInfo.json",
		},
		baseTags:     []string{"sling", "auth-oracle"},
		siblingGuard: true,
		eval: func(res aem.ProbeResult) (verdict, bool) {
			if res.Status != 200 || !strings.Contains(res.Body, "userID") {
				return verdict{}, false
			}
			return verdict{
				name:     "AEM Sling Session Info Servlet Exposed",
				severity: severity.Low,
				evidence: []string{"Sling sessionInfo servlet exposes userID"},
			}, true
		},
	},
	{
		id: "loginstatus",
		paths: []string{
			"/system/sling/loginstatus",
		},
		baseTags:     []string{"sling", "auth-oracle"},
		siblingGuard: true,
		eval: func(res aem.ProbeResult) (verdict, bool) {
			if res.Status != 200 {
				return verdict{}, false
			}
			b := res.Body
			// An authenticated admin oracle is a much stronger signal than the
			// unauthenticated challenge.
			if aem.HasAny(b, "authenticated=true", `"authenticated":true`) && aem.HasAny(b, "userid=admin", "userID=admin") {
				return verdict{
					name:     "AEM LoginStatus Servlet - Authenticated as admin",
					severity: severity.High,
					evidence: []string{"loginstatus reports authenticated admin session"},
				}, true
			}
			if aem.HasAny(b, "CREDENTIAL_CHALLENGE", "authenticated=", `"authenticated":`) {
				return verdict{
					name:     "AEM LoginStatus Servlet Exposed",
					severity: severity.Low,
					evidence: []string{"loginstatus servlet reachable (auth brute-force oracle)"},
				}, true
			}
			return verdict{}, false
		},
	},
	{
		id: "merge-metadata",
		paths: []string{
			"/libs/dam/merge/metadata.html?path=/etc&.ico",
		},
		baseTags:     []string{"dam", "info-disclosure"},
		siblingGuard: false,
		eval: func(res aem.ProbeResult) (verdict, bool) {
			if res.Status != 200 || !strings.Contains(res.Body, "assetPaths") {
				return verdict{}, false
			}
			return verdict{
				name:     "AEM DAM MergeMetadata Servlet Exposed",
				severity: severity.Low,
				evidence: []string{"MergeMetadata servlet reachable"},
			}, true
		},
	},
	{
		id: "audit-servlet",
		paths: []string{
			"/bin/msm/audit",
		},
		baseTags:     []string{"msm", "info-disclosure"},
		siblingGuard: true,
		eval: func(res aem.ProbeResult) (verdict, bool) {
			if res.Status != 200 || !aem.IsJSONContentType(res.ContentType) {
				return verdict{}, false
			}
			b := res.Body
			if !strings.Contains(b, `"results"`) || strings.Contains(b, `"entries":[]`) {
				return verdict{}, false
			}
			return verdict{
				name:     "AEM MSM Audit Servlet Exposed",
				severity: severity.Low,
				evidence: []string{"MSM audit servlet returns audit entries"},
			}, true
		},
	},
	{
		id: "truststore",
		paths: []string{
			"/etc/truststore/truststore.p12",
		},
		baseTags:     []string{"secrets", "certificate"},
		siblingGuard: false,
		eval: func(res aem.ProbeResult) (verdict, bool) {
			if res.Status != 200 || len(res.Body) < 1000 {
				return verdict{}, false
			}
			ct := strings.ToLower(res.ContentType)
			if strings.Contains(ct, "html") {
				return verdict{}, false
			}
			if !aem.HasAny(ct, "pkcs12", "octet-stream", "x-pkcs12", "text/plain") {
				return verdict{}, false
			}
			// Reject error/soft-404 pages that some servers return with 200.
			if aem.HasAny(res.Body, "not found", "Request Rejected", "Access Denied", "<html", "<!DOCTYPE") {
				return verdict{}, false
			}
			return verdict{
				name:     "AEM TrustStore File Exposed",
				severity: severity.Medium,
				evidence: []string{"truststore.p12 downloadable (certificate/key material)"},
			}, true
		},
	},
}
