package modkit

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// IsURLPathInsertionPoint reports whether t addresses a segment of the URL path
// (a folder or the filename) rather than a parameter, header, cookie or body
// value.
//
// The distinction matters to every file-read module, because a payload injected
// into a URL path segment is not injected into anything the application
// interprets — it simply becomes the request target. `AllParamTypes` and
// `URLParamTypes` both include the two path types, so a module that declares
// either is asked to test path segments whether or not its payloads make sense
// there. See DocrootFetchNotInclusion.
func IsURLPathInsertionPoint(t httpmsg.InsertionPointType) bool {
	return t == httpmsg.INS_URL_PATH_FOLDER || t == httpmsg.INS_URL_PATH_FILENAME
}

// docrootPublishableTargets are file paths, relative to a web root, that a
// deployment can legitimately publish *into the served directory* — a build that
// copies its tree into an S3 bucket ships the .env, .git/ and .htaccess along
// with it; a war root holds WEB-INF/. Reaching one of these proves only that it
// is published, never that anything included it.
//
// Membership is what separates them from the other file-read targets: no web
// root serves /etc/passwd, windows/win.ini or /proc/self/environ, so a 200
// carrying that content really is a traversal out of the web root, whatever
// insertion point requested it.
var docrootPublishableTargets = map[string]struct{}{
	".env": {}, ".git/head": {}, ".htaccess": {}, ".htpasswd": {},
	"web-inf/web.xml": {}, "web.config": {},
}

// DocrootPublishableTarget reports whether a file-read payload names a file a
// web root can legitimately publish (see docrootPublishableTargets), ignoring
// any leading traversal. It is a positive allowlist keyed on the target file, so
// an unrecognised payload — a stream wrapper such as
// `php://filter/convert.base64-encode/resource=index.php`, or a target added
// later — falls through as *not* publishable and keeps the module's own
// severity. That is the safe default: the cost of a miss is the old false
// positive returning for one payload, never a real inclusion silently
// downgraded.
func DocrootPublishableTarget(payload string) bool {
	target := strings.ToLower(payload)
	for {
		switch {
		case strings.HasPrefix(target, "../"):
			target = target[3:]
		case strings.HasPrefix(target, "./"):
			target = target[2:]
		case strings.HasPrefix(target, "/"):
			target = target[1:]
		default:
			_, ok := docrootPublishableTargets[target]
			return ok
		}
	}
}

// DocrootFetchNotInclusion reports whether a file-read payload can only ever
// produce a direct HTTP fetch of a published file rather than evidence of
// server-side inclusion, given the insertion point it would be injected into.
//
// Replacing a URL path segment with `.htaccess` yields `GET /.htaccess`; the
// `../` variants normalize back to exactly the same request. When the origin
// genuinely publishes that file the server answers 200 with real file content,
// and a body-only confirm step cannot tell a filesystem read apart from an
// ordinary static fetch. Callers must therefore treat the result as *exposure*,
// not inclusion: report it with DocrootFetchInfo instead of the module's own
// file-inclusion severity.
func DocrootFetchNotInclusion(ipType httpmsg.InsertionPointType, payload string) bool {
	return IsURLPathInsertionPoint(ipType) && DocrootPublishableTarget(payload)
}

// docrootFetchDesc explains the exposure to a reader who would otherwise see an
// LFI-shaped module name and assume injection.
const docrootFetchDesc = `**What it means:** The file below is published under the web root and is served to anyone who requests its URL. No injection or path traversal is involved — the scanner reached it with an ordinary GET, which is why this is reported as informational rather than as file inclusion.

**How it's exploited:** An attacker fetches the URL directly. Impact depends entirely on the file's contents: rewrite rules and framework config disclose internal routing and stack details, while a .env, .git/ or credentials file is a direct secret leak and should be treated as an incident.

**Fix:** Stop deploying the file into the served directory, or block it at the web server/CDN. Rotate anything secret it contains.`

// DocrootFetchInfo builds the informational Info block for a file that turned
// out to be published under the web root and fetchable at its own URL, rather
// than read through an inclusion sink. targetFile names the file that was
// retrieved (".htaccess", "WEB-INF/web.xml", …).
//
// Modules use this so the direct-fetch case is neither silently dropped nor
// reported at file-inclusion severity — it is a real, if minor, observation, and
// one that a High/Critical label badly misrepresents.
func DocrootFetchInfo(targetFile string) output.Info {
	return output.Info{
		Name:        "Web-Root File Exposed (Direct Fetch, Not Inclusion)",
		Description: fmt.Sprintf("%s\n\n**File:** `%s`", docrootFetchDesc, targetFile),
		Severity:    severity.Info,
		Confidence:  severity.Certain,
		Tags:        []string{"exposure", "config-file", "info"},
	}
}
