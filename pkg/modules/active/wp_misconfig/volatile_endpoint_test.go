package wp_misconfig

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestScanPerRequest_ParkedPoolIsNotAWordPressInstaller is the regression guard
// for a Critical false positive found by sweeping a round-robin backend pool.
//
// Two defects combined. The installer probe accepted the bare word
// "installation", which an Apache Ubuntu default page carries in prose. And both
// catch-all guards (ConfirmNotSoft404, SiblingServesAnyMarker) compare the probe
// against a SINGLE control fetch, so on a host that answers every path with one
// of two different pages the control lands on the other backend, the bodies
// differ, and the wildcard shell is declared "not a soft 404".
//
// A parked host that 200s every path must yield nothing, whichever backend
// answers which probe. This is an outcome assertion over both fixes, not a
// gate-isolation test — the marker change alone is enough to suppress this
// particular pool, and TestInstallerMarkersRejectProseAndKeepRealInstaller pins
// that half directly.
func TestScanPerRequest_ParkedPoolIsNotAWordPressInstaller(t *testing.T) {
	t.Parallel()
	var hits int64
	srv := httptest.NewServer(modtest.RoundRobinHandler(&hits,
		modtest.ApacheDefaultPageRHEL, modtest.ApacheDefaultPageUbuntu))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, res, "a parked host serving Apache default pages for every path runs no WordPress")
}

// TestInstallerMarkersRejectProseAndKeepRealInstaller pins the marker change: the
// tokens must identify WordPress's install.php specifically rather than any page
// that happens to discuss an "installation".
func TestInstallerMarkersRejectProseAndKeepRealInstaller(t *testing.T) {
	t.Parallel()
	var installer *wpProbe
	for i := range wpProbes {
		if wpProbes[i].path == "/wp-admin/install.php" {
			installer = &wpProbes[i]
			break
		}
	}
	require.NotNil(t, installer, "installer probe missing from the probe table")

	matches := func(body string) bool {
		for _, mk := range installer.markers {
			if strings.Contains(body, mk) {
				return true
			}
		}
		return false
	}

	require.False(t, matches(modtest.ApacheDefaultPageUbuntu),
		"an Apache default page discussing an installation is not a WordPress installer")
	require.False(t, matches(modtest.ApacheDefaultPageRHEL))

	// The real installer: step 0 (language chooser) and step 1 (setup form). Both
	// load the installer stylesheet; the setup form also carries weblog_title.
	langChooser := `<html><head><title>WordPress &rsaquo; Installation</title>` +
		`<link rel='stylesheet' id='install-css' href='/wp-admin/css/install.min.css' /></head>` +
		`<body class="wp-core-ui language-chooser"><form id="setup" method="post"></form></body></html>`
	setupForm := `<html><body class="wp-core-ui"><form id="setup" method="post" action="?step=2">` +
		`<label for="weblog_title">Site Title</label><input name="weblog_title" type="text" /></form></body></html>`

	require.True(t, matches(langChooser), "the installer language chooser must still be detected")
	require.True(t, matches(setupForm), "the installer setup form must still be detected")
}
