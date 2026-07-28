package wp_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

type wpProbe struct {
	path        string
	name        string
	markers     []string // at least one must match
	antiMarkers []string // if any match, skip (FP indicator)
	sev         severity.Severity
	desc        string
}

var wpProbes = []wpProbe{
	// wp-config.php direct access
	{
		path:        "/wp-config.php",
		name:        "wp-config.php Exposed",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY", "LOGGED_IN_SALT", "DB_PASSWORD"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "<HTML"},
		sev:         severity.Critical,
		desc:        "WordPress configuration file served as plaintext, exposing database credentials and auth salts",
	},
	// wp-config.php backup variants
	{
		path:        "/wp-config.php~",
		name:        "wp-config.php Backup (~)",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Editor backup of wp-config.php exposed with database credentials",
	},
	{
		path:        "/wp-config.php.old",
		name:        "wp-config.php Backup (.old)",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Old backup of wp-config.php exposed with database credentials",
	},
	{
		path:        "/wp-config.php.save",
		name:        "wp-config.php Backup (.save)",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Save file of wp-config.php exposed with database credentials",
	},
	{
		path:        "/wp-config.php.swp",
		name:        "wp-config.php Vim Swap",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Vim swap file of wp-config.php exposed with database credentials",
	},
	{
		path:        "/wp-config.php.txt",
		name:        "wp-config.php Plaintext Copy",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Plaintext copy of wp-config.php exposed with database credentials",
	},
	{
		path:        "/wp-config.php.bak",
		name:        "wp-config.php Backup (.bak)",
		markers:     []string{"DB_NAME", "DB_USER", "AUTH_KEY"},
		antiMarkers: []string{"<html", "<!DOCTYPE"},
		sev:         severity.Critical,
		desc:        "Backup copy of wp-config.php exposed with database credentials",
	},
	// Debug log
	{
		path:        "/wp-content/debug.log",
		name:        "WordPress Debug Log",
		markers:     []string{"PHP Warning", "PHP Fatal error", "Stack trace", "wpdb", "PHP Notice"},
		antiMarkers: []string{"<html", "<!DOCTYPE", "Index of"},
		sev:         severity.High,
		desc:        "WordPress debug log exposed, potentially containing stack traces, SQL queries, filesystem paths, and plugin versions",
	},
	// Informational files
	{
		path:    "/readme.html",
		name:    "WordPress Readme",
		markers: []string{"WordPress", "wordpress.org"},
		sev:     severity.Info,
		desc:    "WordPress readme.html exposed, disclosing WordPress version",
	},
	{
		path:    "/license.txt",
		name:    "WordPress License File",
		markers: []string{"WordPress", "GNU General Public License"},
		sev:     severity.Info,
		desc:    "WordPress license.txt exposed, confirming WordPress installation",
	},
	// Installer/repair endpoints
	{
		path: "/wp-admin/install.php",
		name: "WordPress Installer",
		// Require installer-page tokens, not the bare "WordPress" brand string (every
		// WP page carries it). The "Already Installed" screen is the same endpoint
		// returning a benign 200, so anti-marker it out.
		//
		// "installation" was removed: markers are matched case-sensitively against the
		// raw body, so the lowercase word never matched WordPress's own
		// "WordPress &rsaquo; Installation" title — it only ever matched incidental
		// English prose, and it awarded Critical for it (an Apache "after installation
		// on Ubuntu systems" default page on a host that 200s every path). The
		// replacements are unique to install.php and cover both of its steps: the
		// installer stylesheet is loaded by the language chooser AND the setup form,
		// and weblog_title is the setup form's site-title field.
		markers:     []string{"wp-install", "weblog_title", "wp-admin/css/install"},
		antiMarkers: []string{"Already Installed", "already installed", "already been installed"},
		sev:         severity.Critical,
		desc:        "WordPress installer endpoint accessible — site may be in an unfinished installation state",
	},
	{
		path: "/wp-admin/maint/repair.php",
		name: "WordPress DB Repair",
		// "Repair Database" is the action button shown only when WP_ALLOW_REPAIR is
		// actually enabled. The bare word "repair" AND the constant name itself both
		// appear on the instructions page that renders when the feature is OFF (it
		// tells you to define WP_ALLOW_REPAIR), so neither can gate this finding.
		markers: []string{"Repair Database", "Repair and Optimize Database"},
		sev:     severity.High,
		desc:    "WordPress database repair endpoint is accessible, indicating WP_ALLOW_REPAIR is enabled",
	},
	// Directory listings
	{
		path:    "/wp-content/uploads/",
		name:    "WordPress Uploads Directory Listing",
		markers: []string{"Index of /wp-content/uploads", "Parent Directory"},
		sev:     severity.Medium,
		desc:    "WordPress uploads directory listing enabled, exposing uploaded files",
	},
	{
		path:    "/wp-content/plugins/",
		name:    "WordPress Plugins Directory Listing",
		markers: []string{"Index of /wp-content/plugins", "Parent Directory"},
		sev:     severity.Medium,
		desc:    "WordPress plugins directory listing enabled, exposing installed plugin slugs",
	},
	{
		path:    "/wp-content/",
		name:    "WordPress Content Directory Listing",
		markers: []string{"Index of /wp-content", "Parent Directory"},
		sev:     severity.Medium,
		desc:    "WordPress content directory listing enabled",
	},
	// Cron
	{
		path:    "/wp-cron.php",
		name:    "WordPress Cron Externally Triggerable",
		markers: []string{}, // 200 with empty body is the expected "success" for wp-cron
		sev:     severity.Low,
		desc:    "WordPress cron endpoint is externally triggerable, which can be abused for DoS or resource exhaustion",
	},
	// Common backup archives
	{
		path:    "/wp.sql",
		name:    "WordPress SQL Dump",
		markers: []string{"CREATE TABLE", "INSERT INTO", "wp_users", "wp_options"},
		sev:     severity.Critical,
		desc:    "WordPress SQL dump exposed, potentially containing full database with user credentials",
	},
	{
		path:    "/dump.sql",
		name:    "SQL Dump (WordPress)",
		markers: []string{"wp_users", "wp_options", "wp_posts"},
		sev:     severity.Critical,
		desc:    "SQL dump with WordPress tables exposed",
	},
}
