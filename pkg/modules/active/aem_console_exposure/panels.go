package aem_console_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

// panel is a single AEM console/admin surface with the paths it lives at and the
// co-occurring title/body markers that uniquely identify it. markers is an
// AND-across-groups / OR-within-group set (modkit.MatchAllGroups): every group
// must have a hit, so a finding needs the specific combination only the real
// panel emits — a bare "Search" or "Users" word cannot fire it.
type panel struct {
	id       string
	name     string
	paths    []string
	markers  [][]string
	severity severity.Severity
	tags     []string
	ref      []string
}

// panels is the catalog of internet-should-never-reach AEM consoles. RCE-capable
// surfaces (Groovy console, ACS Fiddle, GetDocumentServlet) live in aem_rce; login
// panels live in aem_fingerprint. This module owns the repository/admin tooling.
var panels = []panel{
	{
		id:    "crxde-lite",
		name:  "AEM CRXDE Lite Exposed",
		paths: []string{"/crx/de/index.jsp"},
		markers: [][]string{
			{"<title>CRXDE Lite</title>", "CRXDE Lite"},
		},
		severity: severity.High,
		tags:     []string{"crx", "jcr"},
		ref:      []string{"https://helpx.adobe.com/experience-manager/6-5/sites/developing/using/developing-with-crxde-lite.html"},
	},
	{
		id:    "crx-packmgr",
		name:  "AEM CRX Package Manager Exposed",
		paths: []string{"/crx/packmgr/index.jsp"},
		markers: [][]string{
			{"<title>CRX Package Manager</title>", "CRX Package Manager"},
		},
		severity: severity.High,
		tags:     []string{"crx", "package-manager"},
		ref:      []string{"https://helpx.adobe.com/experience-manager/6-5/sites/administering/using/package-manager.html"},
	},
	{
		id:    "crx-explorer-browser",
		name:  "AEM CRX Content Explorer Exposed",
		paths: []string{"/crx/explorer/browser/index.jsp"},
		markers: [][]string{
			{"Content Explorer"},
			{"crx.default", "Workspace"},
		},
		severity: severity.High,
		tags:     []string{"crx", "jcr"},
		ref:      []string{"https://blog.assetnote.io/2021/11/08/aem-vulnerabilities/"},
	},
	{
		id:    "crx-explorer-nodetypes",
		name:  "AEM CRX Node Types Explorer Exposed",
		paths: []string{"/crx/explorer/nodetypes/index.jsp"},
		markers: [][]string{
			{"Registered Node Types"},
			{"nodetypeadmin"},
		},
		severity: severity.Medium,
		tags:     []string{"crx", "jcr"},
	},
	{
		id:    "crx-explorer-namespace",
		name:  "AEM CRX Namespace Editor Exposed",
		paths: []string{"/crx/explorer/ui/namespace_editor.jsp"},
		markers: [][]string{
			{"<title>Namespaces</title>"},
			{"registered in the repository"},
		},
		severity: severity.Medium,
		tags:     []string{"crx", "jcr"},
	},
	{
		id:    "crx-explorer-search",
		name:  "AEM CRX Search Explorer Exposed",
		paths: []string{"/crx/explorer/ui/search.jsp"},
		markers: [][]string{
			{"<title>Search</title>"},
			{"/crx/explorer/ui/"},
		},
		severity: severity.Medium,
		tags:     []string{"crx", "jcr"},
	},
	{
		id:    "acs-commons",
		name:  "AEM ACS Commons Tooling Exposed",
		paths: []string{"/etc/acs-commons/jcr-compare.html", "/etc/acs-commons/version-compare.html", "/etc/acs-commons/oak-index-manager.html", "/etc/acs-commons/workflow-remover.html"},
		markers: [][]string{
			{"| ACS AEM Commons"},
			{"JCR Compare", "Version Compare", "Oak Index Manager", "Workflow Remover"},
		},
		severity: severity.Medium,
		tags:     []string{"acs-commons"},
		ref:      []string{"https://adobe-consulting-services.github.io/acs-aem-commons/"},
	},
	{
		id:    "misc-admin",
		name:  "AEM Miscellaneous Admin Dashboard Exposed",
		paths: []string{"/miscadmin"},
		markers: [][]string{
			{"<title>AEM Tools</title>", "<title>CQ Tools</title>"},
		},
		severity: severity.Medium,
		tags:     []string{"admin"},
	},
	{
		id:    "security-users",
		name:  "AEM Security Users Admin Exposed",
		paths: []string{"/libs/granite/security/content/useradmin.html"},
		markers: [][]string{
			{"AEM Security | Users"},
			{`trackingelement="create user"`, "create user"},
		},
		severity: severity.Medium,
		tags:     []string{"admin", "users"},
	},
	{
		id:    "offloading-browser",
		name:  "AEM Offloading Browser Exposed",
		paths: []string{"/libs/granite/offloading/content/view.html"},
		markers: [][]string{
			{"Offloading Browser"},
			{">CLUSTER</th>", "CLUSTER"},
		},
		severity: severity.Medium,
		tags:     []string{"admin"},
	},
	{
		id:    "bulkeditor",
		name:  "AEM BulkEditor Exposed",
		paths: []string{"/etc/importers/bulkeditor.html"},
		markers: [][]string{
			{"<title>AEM BulkEditor</title>", "AEM BulkEditor"},
		},
		severity: severity.Low,
		tags:     []string{"admin"},
	},
	{
		id:    "link-checker",
		name:  "AEM External Link Checker Exposed",
		paths: []string{"/etc/linkchecker.html", "/var/linkchecker.html"},
		markers: [][]string{
			{"<title>External Link Checker</title>", "External Link Checker"},
		},
		severity: severity.Low,
		tags:     []string{"admin", "ssrf-capable"},
	},
	{
		id:    "disk-usage",
		name:  "AEM Disk Usage Report Exposed",
		paths: []string{"/etc/reports/diskusage.html"},
		markers: [][]string{
			{"Disk Usage /"},
			{"<th>nodes</th>", "nodes"},
		},
		severity: severity.Low,
		tags:     []string{"info-disclosure"},
	},
	{
		id:    "dumplibs",
		name:  "AEM Client Libraries Debug (dumplibs) Exposed",
		paths: []string{"/libs/cq/ui/content/dumplibs.html", "/libs/granite/ui/content/dumplibs.html"},
		markers: [][]string{
			{"Client Libraries"},
			{"categories", "clientlib"},
		},
		severity: severity.Low,
		tags:     []string{"info-disclosure"},
	},
	{
		id:    "felix-webconsole",
		name:  "AEM Felix/OSGi Web Console Exposed (Unauthenticated)",
		paths: []string{"/system/console/bundles", "/system/console"},
		markers: [][]string{
			{"Web Console"},
			{"Adobe Experience Manager", "Apache Felix", "org.apache.felix"},
		},
		// An anonymous 200 here is RCE-capable (a malicious OSGi bundle can be
		// installed). A 401 challenge does not match, so a protected console is not
		// reported. Default-credential access to it is handled by aem_default_credentials.
		severity: severity.High,
		tags:     []string{"osgi", "felix", "rce-capable"},
		ref:      []string{"https://helpx.adobe.com/experience-manager/6-5/sites/administering/using/security-checklist.html"},
	},
	{
		id:    "osgi-configmgr",
		name:  "AEM OSGi Configuration Manager Exposed",
		paths: []string{"/system/console/configMgr"},
		markers: [][]string{
			{"org.apache.felix.webconsole", "pluginRoot"},
			{"Configuration", "configMgr"},
		},
		severity: severity.High,
		tags:     []string{"osgi", "felix", "config-exposure"},
	},
}
