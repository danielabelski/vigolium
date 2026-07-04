package jsvendor

import (
	"regexp"
	"strings"
)

// vendorDomains are hosts that serve only third-party analytics, telemetry,
// captcha, bot-protection, payment, chat/consent, or auth SDK code — never
// first-party application logic. A script fetched from any of these is skipped.
//
// Kept separate from cdnDomains (generic CDN library hosts) so the intent is
// clear and each list can grow independently.
var vendorDomains = []string{
	// --- Analytics / product telemetry ---
	"google-analytics.com",
	"ssl.google-analytics.com",
	"www.google-analytics.com",
	"analytics.google.com",
	"googletagmanager.com",
	"googletagservices.com",
	"googlesyndication.com",
	"googleadservices.com",
	"doubleclick.net",
	"stats.g.doubleclick.net",
	"segment.com",
	"segment.io",
	"cdn.segment.com",
	"amplitude.com",
	"cdn.amplitude.com",
	"api.amplitude.com",
	"api2.amplitude.com",
	"mixpanel.com",
	"cdn.mxpnl.com",
	"api.mixpanel.com",
	"hotjar.com",
	"static.hotjar.com",
	"script.hotjar.com",
	"insights.hotjar.com",
	"fullstory.com",
	"edge.fullstory.com",
	"rs.fullstory.com",
	"heapanalytics.com",
	"cdn.heapanalytics.com",
	"heap.io",
	"clarity.ms",
	"www.clarity.ms",
	"c.clarity.ms",
	"plausible.io",
	"matomo.cloud",
	"cloudflareinsights.com",
	"static.cloudflareinsights.com",
	"cdn.mouseflow.com",
	"mouseflow.com",
	"cdn.optimizely.com",
	"logx.optimizely.com",
	"analytics.tiktok.com",
	"connect.facebook.net",
	"snap.licdn.com",
	"px.ads.linkedin.com",
	"sc-static.net",
	"tr.snapchat.com",
	"ct.pinterest.com",
	"s.pinimg.com",
	"static.ads-twitter.com",
	"analytics.twitter.com",
	"track.hubspot.com",
	"js.hs-scripts.com",
	"js.hs-analytics.net",
	"js.hsforms.net",
	"munchkin.marketo.net",
	// Product analytics / session replay
	"posthog.com",
	"app.posthog.com",
	"us.posthog.com",
	"eu.posthog.com",
	"us.i.posthog.com",
	"eu.i.posthog.com",
	"us-assets.i.posthog.com",
	"eu-assets.i.posthog.com",
	"cdn.pendo.io",
	"pendo.io",
	"data.pendo.io",
	"rec.smartlook.com",
	"web-sdk.smartlook.com",
	"manager.smartlook.com",
	"cdn.inspectlet.com",
	"hn.inspectlet.com",
	"static.chartbeat.com",
	"ping.chartbeat.net",
	"script.crazyegg.com",
	"tracking.crazyegg.com",
	"dev.visualwebsiteoptimizer.com", // VWO
	"t.contentsquare.net",            // Contentsquare
	"pixel.quantserve.com",
	"secure.quantserve.com",
	"cdn.parsely.com", // Parse.ly
	// Marketing / push SDKs
	"js.appboycdn.com", // Braze
	"static.klaviyo.com",
	"a.klaviyo.com",
	"cdn.onesignal.com",
	"onesignal.com",
	"assets.customer.io",

	// --- Error / performance monitoring ---
	"browser.sentry-cdn.com",
	"js.sentry-cdn.com",
	"sentry.io",
	"cdn.ravenjs.com", // legacy Sentry (raven.js)
	"js-agent.newrelic.com",
	"bam.nr-data.net",
	"bam-cell.nr-data.net",
	"browser-intake-datadoghq.com",
	"datadoghq-browser-agent.com",
	"www.datadoghq-browser-agent.com",
	"sessions.bugsnag.com",
	"notify.bugsnag.com",
	"d2wy8f7a9ursnm.cloudfront.net",
	"cdn.logrocket.io",
	"cdn.lr-ingest.io",
	"logrocket.com",
	"cdn.rollbar.com", // Rollbar
	"rollbar.com",
	"api.rollbar.com",
	"cdn.raygun.io", // Raygun
	"raygun.io",
	"cdn.trackjs.com", // TrackJS
	"usage.trackjs.com",
	"js.honeybadger.io", // Honeybadger
	"api.honeybadger.io",

	// --- Payment SDKs ---
	"js.stripe.com",
	"m.stripe.com",
	"m.stripe.network",
	"checkout.stripe.com",
	"www.paypal.com",
	"www.paypalobjects.com",
	"c.paypal.com",
	"js.braintreegateway.com",
	"assets.braintreegateway.com",
	"client-analytics.braintreegateway.com",
	"cdn.checkout.com",
	"js.checkout.com",
	"web.squarecdn.com",
	"js.squareup.com",
	"checkout.razorpay.com",
	"cdn.razorpay.com",
	"js.adyen.com",

	// --- CAPTCHA ---
	"recaptcha.net",
	"www.recaptcha.net",
	"js.hcaptcha.com",
	"hcaptcha.com",
	"newassets.hcaptcha.com",
	"assets.hcaptcha.com",
	"imgs.hcaptcha.com",
	"challenges.cloudflare.com",
	"client-api.arkoselabs.com",
	"arkoselabs.com",
	"funcaptcha.com",
	"geo.captcha-delivery.com",
	"static.geetest.com", // GeeTest
	"api.geetest.com",
	"gcaptcha4.geetest.com",
	"api.friendlycaptcha.com", // Friendly Captcha
	"cdn.friendlycaptcha.com",

	// --- Bot protection / anti-fraud ---
	"js.datadome.co",
	"api.datadome.co",
	"datadome.co",
	"api-js.datadome.co",
	"c.captcha-delivery.com",
	"fs.captcha-delivery.com",
	"perimeterx.net",
	"px-cdn.net",
	"px-cloud.net",
	"human-security.com", // HUMAN Security (formerly White Ops / PerimeterX)
	"cdn.kasada.io",      // Kasada
	"kasada.io",

	// --- Consent / cookie management ---
	"cdn.cookielaw.org",
	"consent.cookiebot.com",
	"consentcdn.cookiebot.com",
	"js.usercentrics.eu",
	"app.usercentrics.eu",

	// --- Chat / support widgets ---
	"widget.intercom.io",
	"js.intercomcdn.com",
	"api-iam.intercom.io",
	"js.driftt.com",
	"di.driftt.com",
	"client.crisp.chat",
	"settings.crisp.chat",
	"embed.tawk.to",
	"static.zdassets.com",
	"ekr.zdassets.com",
	"zopim.com",
	"wchat.freshchat.com",

	// --- Auth / identity SDKs ---
	"apis.google.com",
	"accounts.google.com",
	"appleid.cdn-apple.com",
	"cdn.auth0.com",
	"alcdn.msauth.net",
	"alcdn.msftauth.net",
}

// vendorPathPatterns are host-agnostic URL-path substrings that identify vendor
// scripts regardless of the serving host — including vendor code proxied through
// the target's own domain (e.g. reCAPTCHA at /recaptcha/api.js, Cloudflare and
// Akamai bot-management sensors). Matched case-insensitively against the path.
var vendorPathPatterns = []string{
	"/recaptcha/",                  // Google reCAPTCHA (filename is api.js)
	"/cdn-cgi/challenge-platform/", // Cloudflare managed challenge / Turnstile
	"/cdn-cgi/scripts/",            // Cloudflare rocket-loader / beacon / email-decode
	"/akam/",                       // Akamai Bot Manager sensor
	"/gtag/js",                     // Google Analytics gtag
	"/gtm.js",                      // Google Tag Manager
	"/analytics.js",                // Universal Analytics
	"/fbevents.js",                 // Facebook pixel
	"/hotjar-",                     // Hotjar runtime
	"/datadome",                    // DataDome bot protection
	"/_incapsula_resource",         // Imperva/Incapsula
}

// vendorContentSignatures are runtime-internal identifiers that appear only in a
// standalone third-party vendor script — not in first-party integration calls.
// They are deliberately the SDK's own bootstrap globals (e.g. ___grecaptcha_cfg,
// GoogleAnalyticsObject, _cf_chl_opt), not the calls an app makes into an SDK
// (grecaptcha.execute, gtag(...)), so an app bundle that merely integrates a
// vendor is not misclassified. IsVendorScriptContent additionally refuses to
// classify any webpack/Next bundle as vendor (see below).
var vendorContentSignatures = []string{
	// Captcha
	"___grecaptcha_cfg", "__recaptcha_api", "grecaptcha/releases",
	// Bot protection
	"_cf_chl_opt", "_cf_chl_ctx", // Cloudflare managed challenge
	"window.DataDome", "ddjskey", // DataDome
	"_pxAppId", "_pxHostUrl", // PerimeterX
	"bmak.startTracking", "bmak.sensor_data", // Akamai Bot Manager
	// Analytics / telemetry (SDK-defined globals, not integration calls)
	"GoogleAnalyticsObject",
	"google_tag_manager",
	"NREUM", "js-agent.newrelic.com", // New Relic browser agent
	"__DD_BROWSER_SDK", "datadoghq-browser-agent", // Datadog RUM/Logs
	"_hjSettings", "hjSiteSettings", // Hotjar
	"_fs_namespace",                             // FullStory
	"analytics.SNIPPET_VERSION",                 // Segment loader
	"window.intercomSettings",                   // Intercom loader
	"__PosthogExtensions__", "posthog.__loaded", // PostHog (often self-hosted via reverse proxy)
	"Rollbar.init", "_rollbarConfig", // Rollbar
	"raygun4js", // Raygun
}

// appBundleMarkers identify a first-party module bundle (webpack/Next/SystemJS).
// Such bundles can legitimately embed vendor SDK calls while still carrying the
// app code worth beautifying, so they are never skipped on content grounds.
var appBundleMarkers = regexp.MustCompile(`__webpack_require__|webpackChunk|webpackJsonp|self\.__next_f|System\.register`)

// IsVendorDomain reports whether host is a known third-party CDN library host
// or a vendor (analytics/telemetry/captcha/bot/payment/SDK) host.
func IsVendorDomain(host string) bool {
	host = strings.ToLower(host)
	return hostMatchesAny(host, cdnDomains) || hostMatchesAny(host, vendorDomains)
}

// IsVendorPath reports whether the URL path matches a host-agnostic vendor path
// marker (reCAPTCHA, Cloudflare/Akamai bot sensors, GA/GTM, etc.).
func IsVendorPath(urlPath string) bool {
	p := strings.ToLower(urlPath)
	for _, pat := range vendorPathPatterns {
		if strings.Contains(p, pat) {
			return true
		}
	}
	return false
}

// IsVendorScriptContent reports whether a script's body is a standalone vendor
// runtime (analytics/telemetry/captcha/bot-protection SDK) rather than
// first-party application code. First-party module bundles (webpack/Next) are
// never classified as vendor, even when they embed vendor SDK calls, so a real
// app bundle is not skipped. Used to catch vendor scripts served from the
// target's own domain or under an obfuscated filename.
func IsVendorScriptContent(body string) bool {
	if body == "" {
		return false
	}
	if appBundleMarkers.MatchString(body) {
		return false
	}
	for _, sig := range vendorContentSignatures {
		if strings.Contains(body, sig) {
			return true
		}
	}
	return false
}
