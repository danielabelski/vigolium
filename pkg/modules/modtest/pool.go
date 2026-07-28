package modtest

import (
	"net/http"
	"strings"
	"sync/atomic"
)

// A round-robin backend pool — a load balancer fronting two mismatched backends,
// so the SAME unmodified request returns one of two unrelated pages depending on
// which backend answers. This is the surface that manufactures phantom
// differentials for every body-diff oracle in the scanner (boolean-blind
// injection, path normalization, cross-ID comparison, header size shifts), and
// the shape modkit.EndpointVolatile exists to reject.
//
// The two pages below are the real Apache defaults from the parked hosts that
// motivated the gate, sized ~4x apart like the originals (5.9 KB vs 11.3 KB).
// The proportions matter to the modules under test: the pages must share almost
// no vocabulary (so they are not "the same page" by textual similarity) and the
// length gap must clear the substantial-body-difference bar (>100 bytes AND
// >=20%), because a pair that failed either bar would let a test pass for the
// wrong reason — the module rejecting the differential on its own rather than on
// the determinism gate.
// Declared as vars rather than consts because the filler is built with
// strings.Repeat. Treat them as read-only.
var (
	// ApacheDefaultPageRHEL is the smaller of the pair.
	ApacheDefaultPageRHEL = "<html><head><title>Test Page for the HTTP Server on Red Hat Enterprise Linux</title></head>" +
		"<body><h1>Red Hat Enterprise Linux Test Page</h1>" +
		"<p>This page is used to test the proper operation of the HTTP server after it has been " +
		"installed. If you can read this page, it means that the HTTP server installed at this site " +
		"is working properly.</p>" +
		"<p>If you are a member of the general public: the fact that you are seeing this page " +
		"indicates that the website you just visited is either experiencing problems or is " +
		"undergoing routine maintenance.</p>" +
		redHatFiller + "</body></html>"

	// ApacheDefaultPageUbuntu is the larger of the pair. It carries the word
	// "installation" in ordinary prose, exactly as the real page does — the token
	// that once earned a Critical WordPress-installer finding on a parked host.
	ApacheDefaultPageUbuntu = "<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>" +
		"<body><h1>Apache2 Ubuntu Default Page</h1>" +
		"<p>It works! This is the default welcome page used to test the correct operation of the " +
		"Apache2 server after installation on Ubuntu systems.</p>" +
		"<p>The configuration layout for an Apache2 web server installation on Ubuntu systems is " +
		"fully documented in the README file referenced below.</p>" +
		ubuntuFiller + "</body></html>"
)

// Filler keeps each page's vocabulary distinct and sets the ~4x length ratio.
var (
	redHatFiller = strings.Repeat("<p>Red Hat filler paragraph.</p>", 40)
	ubuntuFiller = strings.Repeat("<p>Ubuntu filler paragraph with entirely unrelated vocabulary.</p>", 160)
)

// RoundRobinHandler serves bodies in rotation — one per request, ignoring the
// request entirely — and counts every hit into hits, which the caller owns so a
// test can assert how many requests a gate actually spent. Pass at least one
// body; with a single body it degenerates into a stable endpoint, which is the
// useful negative control.
func RoundRobinHandler(hits *int64, bodies ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt64(hits, 1) - 1
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(bodies[n%int64(len(bodies))]))
	}
}
