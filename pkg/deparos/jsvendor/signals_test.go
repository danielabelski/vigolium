package jsvendor

import "testing"

func TestIsVendorDomain(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// Analytics / telemetry
		{"www.google-analytics.com", true},
		{"cdn.segment.com", true},
		{"static.hotjar.com", true},
		{"browser.sentry-cdn.com", true},
		{"js-agent.newrelic.com", true},
		{"o123.ingest.sentry.io", true}, // suffix of sentry.io
		// Payment
		{"js.stripe.com", true},
		{"js.braintreegateway.com", true},
		// Product analytics / telemetry (added set)
		{"us.i.posthog.com", true},
		{"posthog.com", true},
		{"cdn.rollbar.com", true},
		{"cdn.raygun.io", true},
		{"js.honeybadger.io", true},
		{"cdn.pendo.io", true},
		// Captcha / bot
		{"js.hcaptcha.com", true},
		{"challenges.cloudflare.com", true},
		{"js.datadome.co", true},
		{"static.geetest.com", true},
		{"api.friendlycaptcha.com", true},
		{"human-security.com", true},
		{"cdn.kasada.io", true},
		// CDN (delegates to IsCDNDomain)
		{"cdn.jsdelivr.net", true},
		// First-party
		{"app.target.com", false},
		{"api.example.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsVendorDomain(c.host); got != c.want {
			t.Errorf("IsVendorDomain(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestIsVendorPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/recaptcha/api.js", true},                                   // reCAPTCHA (filename api.js)
		{"/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1", true}, // Cloudflare bot
		{"/akam/13/abc123", true},                                     // Akamai sensor
		{"/gtag/js?id=G-XXXX", true},                                  // GA gtag
		{"/gtm.js", true},                                             // GTM
		{"/static/chunks/app.js", false},                              // first-party
		{"/_next/static/chunks/main-abc.js", false},                   // first-party
	}
	for _, c := range cases {
		if got := IsVendorPath(c.path); got != c.want {
			t.Errorf("IsVendorPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestIsVendorScriptContent(t *testing.T) {
	// Standalone vendor runtimes → vendor.
	vendor := []string{
		`var ___grecaptcha_cfg={clients:{}};function x(){}`,
		`window._cf_chl_opt={cvId:"3",cType:"managed"};`,
		`var _pxAppId="PXabc123";var _pxHostUrl="//collector.px";`,
		`(function(){window.GoogleAnalyticsObject="ga";ga=function(){};})();`,
		`;NREUM.init={};window.NREUM||(NREUM={});`,
		`window._hjSettings={hjid:123,hjsv:6};`,
	}
	for _, v := range vendor {
		if !IsVendorScriptContent(v) {
			t.Errorf("expected vendor content: %.40q", v)
		}
	}

	// First-party code → not vendor.
	appish := []string{
		`export async function getUser(id){return fetch("/api/users/"+id)}`,
		`grecaptcha.execute("sitekey",{action:"login"}).then(t=>submit(t));`, // integration call, not runtime
		`window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}gtag("config","G-X");`,
		``,
	}
	for _, a := range appish {
		if IsVendorScriptContent(a) {
			t.Errorf("did not expect vendor content: %.60q", a)
		}
	}

	// An app bundle that embeds a vendor marker must NOT be classified as vendor
	// (webpack/Next bundles carry first-party code worth beautifying).
	bundleWithVendor := `(self.webpackChunk=self.webpackChunk||[]).push([[1],{5:function(){window.GoogleAnalyticsObject="ga"}}]);`
	if IsVendorScriptContent(bundleWithVendor) {
		t.Error("an app bundle embedding a vendor marker must not be classified as vendor")
	}
}

func TestShouldSkipJSPathExtraction_Extended(t *testing.T) {
	skip := []struct{ host, path string }{
		{"www.google.com", "/recaptcha/api.js"},                               // reCAPTCHA via path (was a known gap)
		{"js.stripe.com", "/v3/"},                                             // vendor domain
		{"target.com", "/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1"}, // CF bot, first-party host
		{"target.com", "/static/gtag.js"},                                     // analytics filename
	}
	for _, c := range skip {
		if !ShouldSkipJSPathExtraction(c.host, c.path) {
			t.Errorf("ShouldSkipJSPathExtraction(%q,%q) = false, want true", c.host, c.path)
		}
	}
	// First-party app bundle is not skipped.
	if ShouldSkipJSPathExtraction("target.com", "/_next/static/chunks/app.js") {
		t.Error("first-party app bundle should not be skipped")
	}
}
