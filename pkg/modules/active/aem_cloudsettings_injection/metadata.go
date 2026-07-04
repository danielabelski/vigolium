package aem_cloudsettings_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-cloudsettings-injection"
	ModuleName  = "AEM Cloud Settings Pre-Auth Node Write / EL Injection"
	ModuleShort = "Detects the AEM BulkImportConfigServlet pre-authentication node write (CVE-2025-54246) and the Expression Language injection it enables (CVE-2025-54247/54248) by writing a benign marker / 7*7 probe and reading it back through the ConfDeliveryServlet"
)

var (
	ModuleDesc = `**What it means:** AEM's BulkImportConfigServlet writes request parameters into ` + "`/conf/global/settings/dam/import/cloudsettings`" + ` under a privileged account, and the ConfDeliveryServlet reads them back — also privileged. Together they give an unauthenticated arbitrary JCR-property write with a read-back channel (CVE-2025-54246). When the written ` + "`sling:resourceType`" + ` points at a JSP that evaluates a property as Expression Language, it becomes server-side EL injection (CVE-2025-54247/54248) that leaks OSGi secrets.

**How it's exploited:** POST ` + "`importSource=UrlBased&sling:resourceType=<jsp>&action=x#{7*7}y`" + `, then read the node back through the ConfDeliveryServlet; ` + "`x49y`" + ` proves the EL evaluated.

**Fix:** Apply the GRANITE-61551 hotfix and deny anonymous access to ` + "`/conf`" + ` and ` + "`/etc/cloudsettings`" + ` at the dispatcher.`

	ModuleConfirmation = "Confirmed when a benign marker property POSTed to the BulkImportConfigServlet is read back verbatim through the ConfDeliveryServlet (pre-auth write), and/or a x#{7*7}y probe is read back as x49y with the literal #{7*7} absent (EL evaluated server-side), reproducing across rounds"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"aem", "adobe", "injection", "el-injection", "rce", "acl", "cve", "cve2025", "cms"}
)
