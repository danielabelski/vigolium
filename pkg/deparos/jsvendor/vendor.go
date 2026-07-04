// Package jsvendor classifies JavaScript URLs as third-party vendor assets
// (CDN-hosted libraries, analytics/tracking, captcha, chat/social/payment SDKs)
// versus first-party application code.
//
// It is a leaf package (stdlib only) so both the spider's path-extraction gate
// and the passive js-beautify module can share one source of truth for "skip
// this — it's a vendor blob, not target app code." The carve-outs are
// deliberate: HTTP clients, routers, state management, WebSocket clients, and
// major frameworks are NOT treated as vendor because their bundles frequently
// carry application endpoints/routes.
package jsvendor

import (
	"strings"
)

// cdnDomains contains CDN domains that host third-party libraries.
// JS files from these domains are skipped as they don't contain useful paths.
var cdnDomains = []string{
	// Major CDNs
	"cdn.jsdelivr.net",
	"fastly.jsdelivr.net",
	"cdnjs.cloudflare.com",
	"unpkg.com",
	"npmcdn.com",
	"esm.sh",
	"esm.run",
	"skypack.dev",
	"jspm.dev",
	"ga.jspm.io",

	// Google
	"ajax.googleapis.com",
	"fonts.googleapis.com",
	"fonts.gstatic.com",
	"www.googletagmanager.com",

	// Microsoft
	"ajax.aspnetcdn.com",

	// jQuery/Bootstrap
	"code.jquery.com",
	"stackpath.bootstrapcdn.com",
	"maxcdn.bootstrapcdn.com",
	"netdna.bootstrapcdn.com",

	// Chinese CDNs
	"cdn.bootcdn.net",
	"cdn.bootcss.com",
	"lib.baomitu.com",
	"cdn.staticfile.org",
	"lf1-cdn-tos.bytegoofy.com",
	"lf3-cdn-tos.bytescm.com",
	"lf6-cdn-tos.bytecdntp.com",
	"s1.hdslb.com",
	"s2.hdslb.com",

	// Font Awesome
	"use.fontawesome.com",
	"kit.fontawesome.com",
	"ka-f.fontawesome.com",

	// Other popular CDNs
	"cdn.tailwindcss.com",
	"cdn.polyfill.io",
	"polyfill.io",
	"cdn.rawgit.com",
	"rawcdn.githack.com",
	"cdn.statically.io",
	"cdn.skypack.dev",
	"yastatic.net",
	"yandex.st",
	"cdnjs.com",
	"raw.githubusercontent.com",
}

// libraryPatterns contains filename patterns for pure UI/visual third-party libraries.
// These are skipped because they contain NO application-specific endpoints or paths.
//
// INTENTIONALLY NOT BLOCKED (may contain API endpoints/routes):
// - HTTP clients (axios, fetch, superagent) - may define API endpoints
// - Routers (vue-router, react-router) - contain application routes
// - State management (redux, mobx, zustand) - may have API configurations
// - WebSocket clients (socket.io, signalr) - may have endpoint URLs
// - Major frameworks (react, vue, angular) - avoid blocking app bundles like "app.react.js"
var libraryPatterns = []string{
	// Core UI frameworks (specific patterns to avoid false positives)
	"jquery.min",
	"jquery.slim",
	"jquery-ui",
	"jquery-migrate",
	"bootstrap.min",
	"bootstrap.bundle",
	"bootstrap-datepicker",
	"jquery",

	// Polyfills (browser compatibility only, no app logic)
	"polyfill.min",
	"core-js.min",
	"core-js-bundle",
	"regenerator-runtime",
	"es5-shim",
	"es6-shim",
	"html5shiv",
	"respond.min",
	"modernizr",

	// Animation/Motion libraries (pure visual effects)
	"gsap.min",
	"gsap-",
	"anime.min",
	"animejs",
	"lottie.min",
	"lottie-web",
	"lottie-player",
	"framer-motion",
	"popmotion",
	"velocity.min",
	"velocity.ui",
	"scrollreveal",
	"scrollmagic",
	"locomotive-scroll",
	"aos.js",
	"rellax.min",
	"parallax.min",
	"skrollr.min",

	// Charts/Visualization (pure rendering, no app endpoints)
	"d3.min",
	"d3.v",
	"chart.min",
	"chart.js",
	"chartjs",
	"highcharts",
	"echarts.min",
	"apexcharts",
	"plotly.min",
	"plotly-",
	"c3.min",
	"nvd3.min",

	// 3D/Games (pure rendering engines)
	"three.min",
	"three.module",
	"babylon.min",
	"babylonjs",
	"pixi.min",
	"pixijs",
	"phaser.min",

	// Icons (pure visual assets)
	"fontawesome",
	"fa-solid",
	"fa-regular",
	"fa-brands",
	"feather-icons",
	"lucide.min",
	"heroicons",

	// UI widgets (pure visual components)
	"swiper.min",
	"swiper-bundle",
	"slick.min",
	"owl.carousel",
	"glide.min",
	"flickity",
	"splide.min",
	"lightbox.min",
	"fancybox",
	"magnific-popup",
	"photoswipe",
	"sweetalert",
	"toastr.min",
	"notyf.min",
	"tippy.min",
	"popper.min",
	"tooltip.min",

	// Date/Time display (formatting only)
	"moment.min",
	"moment-with-locales",
	"dayjs.min",
	"luxon.min",
	"date-fns.min",

	// Code editors (UI rendering only)
	"prism.min",
	"prism.js",
	"highlight.min",
	"codemirror.min",
	"ace.min",
	"ace-builds",
	"monaco-editor",

	// Rich text editors (UI only)
	"tinymce.min",
	"ckeditor",
	"quill.min",
	"summernote",
	"froala",

	// Media players (UI rendering only)
	"video.min",
	"video.js",
	"videojs",
	"plyr.min",
	"mediaelement",
	"jwplayer",
	"howler.min",
	"wavesurfer.min",

	// Maps (rendering only, not map data APIs)
	"leaflet.min",
	"leaflet.js",
	"openlayers.min",
	"mapbox-gl",

	// Analytics/Tracking (third-party services)
	"gtag.js",
	"gtm.js",
	"google-analytics",
	"googletagmanager",
	"hotjar",
	"mixpanel.min",
	"fullstory",
	"mouseflow",
	"crazyegg",
	"optimizely",

	// Social widgets (third-party)
	"twitter-widget",
	"facebook-sdk",
	"platform.twitter",
	"connect.facebook",
	"sharethis",
	"addthis",

	// Chat widgets (third-party services)
	"intercom.min",
	"drift.min",
	"crisp.chat",
	"tawk.to",
	"zendesk",
	"freshchat",
	"livechat",
	"olark",

	// CAPTCHA (third-party services)
	"recaptcha",
	"hcaptcha",
	"turnstile",

	// Payment SDKs (third-party, use specific patterns)
	"stripe.min",
	"paypal.min",
	"paypalobjects",
	"braintree.min",

	// Transpiler runtime (generated code, no app logic)
	"tslib.min",
	"tslib.es",
}

// hostMatchesAny reports whether the (already lowercased) host equals or is a
// subdomain of any domain in list. The subdomain test is done without allocating
// a "."+domain string per entry.
func hostMatchesAny(host string, list []string) bool {
	for _, d := range list {
		if host == d {
			return true
		}
		if len(host) > len(d) && host[len(host)-len(d)-1] == '.' && strings.HasSuffix(host, d) {
			return true
		}
	}
	return false
}

// IsCDNDomain reports whether host is a known third-party CDN domain.
func IsCDNDomain(host string) bool {
	return hostMatchesAny(strings.ToLower(host), cdnDomains)
}

// IsLibraryFile reports whether the URL path's filename matches a known
// third-party library / analytics / captcha / SDK pattern.
func IsLibraryFile(urlPath string) bool {
	// Get filename from path
	lastSlash := strings.LastIndex(urlPath, "/")
	filename := urlPath
	if lastSlash >= 0 && lastSlash < len(urlPath)-1 {
		filename = urlPath[lastSlash+1:]
	}

	filenameLower := strings.ToLower(filename)
	for _, pattern := range libraryPatterns {
		if strings.Contains(filenameLower, pattern) {
			return true
		}
	}
	return false
}

// ShouldSkipJSPathExtraction reports whether a JS URL (given by its host and
// path) is a third-party vendor asset that should be skipped — a CDN/vendor
// domain, a known library/analytics/SDK filename, or a vendor path marker
// (reCAPTCHA, Cloudflare/Akamai bot sensors, GA/GTM, ...) — rather than treated
// as first-party application code. Taking host/path as strings keeps it agnostic
// to the caller's URL type (net/url vs urlutil). For content-based vendor
// detection (vendor code served first-party), see IsVendorScriptContent.
func ShouldSkipJSPathExtraction(host, path string) bool {
	return IsVendorDomain(host) || IsLibraryFile(path) || IsVendorPath(path)
}
