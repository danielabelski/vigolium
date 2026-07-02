package javascript_uri_sink

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "javascript-uri-sink"
	ModuleName  = "JavaScript URI Sink Detection"
	ModuleShort = "Detects javascript: URIs reflected in href/src attributes"
)

var (
	ModuleDesc = `**What it means:** A javascript: protocol URI was found inside a URL-based HTML attribute (href, src, action, or formaction) - a potential XSS sink. It is only exploitable when the URI is built from unvalidated user input. Reported Medium/Firm only when a request parameter value is reflected into the URI; a static, site-authored javascript: URI (no reflected input) is reported Info/Tentative as an observation, and browser no-ops (javascript:void(0)) and framework postback helpers (ASP.NET __doPostBack, document.form.submit()) are not reported at all.

**How it's exploited:** An attacker crafts a link or form whose URL attribute begins with javascript: (including encoded variants) using reflected input; when the victim clicks or submits, the script runs in their session.

**Fix:** Reject or strip javascript: and other non-http schemes, and allow-list only safe protocols like http/https/mailto.`

	ModuleConfirmation = "Confirmed when a request parameter value is reflected into a javascript: URI in a URL-based HTML attribute (Medium/Firm); a static javascript: URI with no reflected input is an Info observation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"xss", "javascript", "light"}
)
