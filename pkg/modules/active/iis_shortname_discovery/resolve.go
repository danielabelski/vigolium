package iis_shortname_discovery

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/internal/resources/wordlists"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

// maxRecurseDepth bounds directory recursion (root plus this many levels).
const maxRecurseDepth = 1

// maxCandidatesPerFragment caps how many wordlist candidates we confirm for a
// single discovered fragment, bounding request cost.
const maxCandidatesPerFragment = 8

// bogusMethod is an invalid HTTP method used for the 405 existence oracle. IIS
// answers 405 Method Not Allowed for a method it recognises as invalid on an
// existing resource, but 404 for a non-existent path.
const bogusMethod = "VIGOLIUMX"

// embeddedWordlists are the built-in deparos lists we reuse as the resolution
// dictionary. file lists carry filenames (often with extensions); dir lists
// carry directory names.
var embeddedWordlists = []string{
	"file-short.txt", "file-long.txt", "fuzz.txt", "dir-short.txt", "dir-long.txt",
}

// staticIISNames are high-value IIS/ASP.NET filenames that may be absent from
// the generic lists but are worth resolving whenever a fragment matches.
var staticIISNames = []string{
	"web.config", "web.config.bak", "web.config.old", "web.config.txt",
	"machine.config", "connectionstrings.config", "appsettings.json",
	"appsettings.production.json", "global.asax", "global.asa", "packages.config",
	"default.aspx", "login.aspx", "admin.aspx", "upload.aspx", "web.debug.config",
	"web.release.config", "applicationhost.config", "backup.zip", "backup.bak",
	"database.mdf", "app_offline.htm", "trace.axd", "elmah.axd",
}

// resolvedName describes a discovered fragment and, when resolution succeeded,
// its confirmed full filename and absolute URL.
type resolvedName struct {
	shortName string // e.g. WEB~1.CON
	fullName  string // e.g. web.config ("" when unresolved)
	url       string // absolute URL (set only when confirmed)
	isDir     bool
	sensitive bool
	reason    string // classification reason (config/backup/source/...)
}

// nameIndex maps an 8.3 short-name key ("FILE83|EXT83") to candidate full names.
type nameIndex struct {
	m    map[string][]string
	seen map[string]struct{}
}

func (idx *nameIndex) add(file83, ext83, full string) {
	key := file83 + "|" + ext83
	dedupKey := key + "\x00" + full
	if _, ok := idx.seen[dedupKey]; ok {
		return
	}
	idx.seen[dedupKey] = struct{}{}
	idx.m[key] = append(idx.m[key], full)
}

func (idx *nameIndex) lookup(file, ext string) []string {
	return idx.m[strings.ToUpper(file)+"|"+strings.ToUpper(ext)]
}

var (
	globalIndex     *nameIndex
	globalIndexOnce sync.Once
)

// resolverIndex builds (once) the shared name index from the embedded wordlists.
func resolverIndex() *nameIndex {
	globalIndexOnce.Do(func() {
		idx := &nameIndex{m: make(map[string][]string), seen: make(map[string]struct{})}
		add := func(words []string) {
			for _, w := range words {
				indexWord(idx, w)
			}
		}
		for _, name := range embeddedWordlists {
			data, err := wordlists.WordlistsFS.ReadFile(name)
			if err != nil {
				zap.L().Debug("IISShortname: embedded wordlist unavailable", zap.String("file", name), zap.Error(err))
				continue
			}
			add(strings.Split(string(data), "\n"))
		}
		add(staticIISNames)
		idx.seen = nil // build-only dedup set; free it once the index is built
		globalIndex = idx
		zap.L().Debug("IISShortname: name index built", zap.Int("keys", len(idx.m)))
	})
	return globalIndex
}

// indexWord adds the plain and checksummed 8.3 forms of one candidate filename.
func indexWord(idx *nameIndex, w string) {
	w = strings.TrimSpace(w)
	if w == "" || strings.HasPrefix(w, "#") {
		return
	}
	file, ext := splitFileExt(w)
	required, f83, e83 := gen8dot3(file, ext)
	if !required || f83 == "" {
		// Windows only creates a tilde alias (which the oracle can reveal) when a
		// short name is actually required.
		return
	}

	// Plain ~1 form.
	idx.add(f83, e83, w)

	// Checksummed (Vista+) form: prefix + 4-hex checksum, keeping the same ext.
	prefixLen := min(2, len(f83))
	prefix := f83[:prefixLen]
	for _, ck := range checksumVariants(w) {
		idx.add(prefix+ck, e83, w)
	}
}

// checksumVariants returns the distinct 4-hex checksums for a filename across
// case variants and both Microsoft checksum algorithms.
func checksumVariants(w string) []string {
	// Dedup the case variants first: most wordlist entries are already
	// single-case, so w == ToLower(w) and the checksum work would repeat.
	variants := []string{w}
	if l := strings.ToLower(w); l != w {
		variants = append(variants, l)
	}
	if u := strings.ToUpper(w); u != w {
		variants = append(variants, u)
	}

	set := make(map[string]struct{}, 6)
	for _, v := range variants {
		if c := checksum(v); c != "" {
			set[c] = struct{}{}
		}
		if c := checksumOriginal(v); c != "" {
			set[c] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	return out
}

// splitFileExt splits a filename into its long file and extension parts (the
// extension is returned without a leading dot). Leading-dot names (".gitignore")
// are treated as extensionless.
func splitFileExt(w string) (file, ext string) {
	if p := strings.LastIndex(w, "."); p > 0 {
		return w[:p], w[p+1:]
	}
	return w, ""
}

// probeResp is a lightweight snapshot of a probe response.
type probeResp struct {
	status   int
	body     []byte
	location string
}

// sendProbeFull sends a probe and returns status, a capped body copy, and the
// Location header. Body is copied before the response is closed.
func sendProbeFull(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, method, path string) (probeResp, error) {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
	if err != nil {
		return probeResp{}, err
	}
	raw, err = httpmsg.SetPath(raw, path)
	if err != nil {
		return probeResp{}, err
	}

	fuzzedReq := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return probeResp{}, err
	}
	defer resp.Close()

	r := resp.Response()
	if r == nil {
		return probeResp{}, fmt.Errorf("nil response")
	}

	body := resp.BodyBytes()
	n := min(len(body), 4096)
	cp := make([]byte, n)
	copy(cp, body[:n])

	loc := ""
	if r.Header != nil {
		loc = r.Header.Get("Location")
	}

	return probeResp{status: r.StatusCode, body: cp, location: loc}, nil
}

// negBaseline captures how the server answers a non-existent path for a given
// extension.
type negBaseline struct {
	status   int
	body     []byte
	unstable bool
}

// resolver carries per-host state for full-name resolution.
type resolver struct {
	idx        *nameIndex
	targetURL  string // scheme://host (no trailing slash)
	neg        map[string]negBaseline
	methodDone bool
	methodOK   bool
}

func newResolver(targetURL string) *resolver {
	return &resolver{
		idx:       resolverIndex(),
		targetURL: strings.TrimRight(targetURL, "/"),
		neg:       make(map[string]negBaseline),
	}
}

// resolveAll resolves every discovered fragment at basePath, then recurses into
// confirmed directories. basePath is a URL path beginning and ending with "/".
func (r *resolver) resolveAll(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath string,
	o *oracle,
	shorts []shortFile,
	reqBudget *requestBudget,
	depth int,
) []resolvedName {
	var out []resolvedName
	var dirs []resolvedName

	for _, sf := range shorts {
		if reqBudget.exhausted() {
			break
		}
		rn := r.resolveOne(ctx, httpClient, basePath, sf, reqBudget)
		out = append(out, rn)
		if rn.isDir && rn.url != "" {
			dirs = append(dirs, rn)
		}
	}

	if depth >= maxRecurseDepth {
		return out
	}

	// Recurse into confirmed directories, re-detecting the oracle per subpath
	// (a subdirectory can have a different negative baseline).
	for _, d := range dirs {
		if reqBudget.exhausted() {
			break
		}
		seg := d.fullName
		if seg == "" {
			seg = strings.TrimSuffix(d.shortName, "/")
		}
		subBase := basePath + escapeSegment(seg) + "/"
		subO := detectVulnerability(ctx, httpClient, subBase, reqBudget)
		if subO == nil {
			continue
		}
		subCM := discoverCharacters(ctx, httpClient, subBase, subO, reqBudget)
		subShorts := enumerate(ctx, httpClient, subBase, subO, subCM, reqBudget)
		if len(subShorts) == 0 {
			continue
		}
		zap.L().Debug("IISShortname: recursing into directory",
			zap.String("dir", subBase), zap.Int("fragments", len(subShorts)))
		out = append(out, r.resolveAll(ctx, httpClient, subBase, subO, subShorts, reqBudget, depth+1)...)
	}

	return out
}

// resolveOne resolves a single fragment: matches candidates from the wordlist,
// confirms existence through independent oracles, and classifies sensitivity.
func (r *resolver) resolveOne(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath string,
	sf shortFile,
	reqBudget *requestBudget,
) resolvedName {
	rn := resolvedName{shortName: sf.String()}

	candidates := r.idx.lookup(sf.file, sf.ext)
	if len(candidates) > maxCandidatesPerFragment {
		candidates = candidates[:maxCandidatesPerFragment]
	}

	for _, full := range candidates {
		if reqBudget.exhausted() {
			break
		}
		if !r.confirm(ctx, httpClient, basePath, full, reqBudget) {
			continue
		}
		rn.fullName = full
		rn.url = r.targetURL + basePath + escapeSegment(full)
		rn.sensitive, rn.reason = classifyName(full)
		break
	}

	// Directory check applies to extensionless fragments whether or not a full
	// name resolved (the short segment is itself a valid path).
	if sf.ext == "" {
		seg := sf.String()
		if rn.fullName != "" {
			seg = rn.fullName
		}
		if r.isDirectory(ctx, httpClient, basePath, seg, reqBudget) {
			rn.isDir = true
			if rn.url == "" {
				rn.url = r.targetURL + basePath + escapeSegment(strings.TrimSuffix(sf.String(), "/"))
			}
		}
	}

	return rn
}

// confirm decides whether fullName exists at basePath using multiple independent
// rounds, dropping the candidate unless the rounds agree.
func (r *resolver) confirm(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath, fullName string,
	reqBudget *requestBudget,
) bool {
	path := basePath + escapeSegment(fullName)

	// Round 1: fetch the candidate.
	reqBudget.inc()
	got, err := sendProbeFull(ctx, httpClient, "GET", path)
	if err != nil {
		return false
	}
	if got.status == 400 || got.status == 404 || got.status == 414 {
		return false
	}

	// Negative control for this extension.
	_, ext := splitFileExt(fullName)
	neg := r.negBaselineFor(ctx, httpClient, basePath, ext, reqBudget)
	distinct := neg.unstable || got.status != neg.status || !modkit.BodiesSimilar(string(got.body), string(neg.body))
	if !distinct {
		return false // indistinguishable from a non-existent path (catch-all / soft-404)
	}

	// Round 2: independent 405-method oracle when the host supports it.
	r.calibrateMethodOracle(ctx, httpClient, basePath, reqBudget)
	if r.methodOK {
		reqBudget.inc()
		m, err := sendProbeFull(ctx, httpClient, bogusMethod, path)
		if err != nil {
			return false
		}
		return m.status == 405 // 405 on an existing resource; two signals agree
	}

	// Fallback (no usable method oracle): require a real-resource status plus a
	// deterministic re-fetch, giving a second independent round.
	if !isResourceStatus(got.status) {
		return false
	}
	reqBudget.inc()
	again, err := sendProbeFull(ctx, httpClient, "GET", path)
	if err != nil || again.status != got.status {
		return false
	}
	return modkit.BodiesSimilar(string(got.body), string(again.body))
}

// negBaselineFor samples (and caches) the response to a non-existent path with
// the given extension. Two samples must agree, else the baseline is unstable.
func (r *resolver) negBaselineFor(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath, ext string,
	reqBudget *requestBudget,
) negBaseline {
	if b, ok := r.neg[ext]; ok {
		return b
	}

	suffix := ""
	if ext != "" {
		suffix = "." + ext
	}

	var b negBaseline
	reqBudget.inc()
	a, errA := sendProbeFull(ctx, httpClient, "GET", basePath+utils.RandomString(12)+suffix)
	reqBudget.inc()
	c, errC := sendProbeFull(ctx, httpClient, "GET", basePath+utils.RandomString(12)+suffix)
	switch {
	case errA != nil || errC != nil:
		b.unstable = true
	case a.status != c.status:
		b.unstable = true
	default:
		b = negBaseline{status: a.status, body: a.body}
	}

	r.neg[ext] = b
	return b
}

// calibrateMethodOracle checks once whether an invalid HTTP method yields 405 on
// an existing resource (basePath) but not on a non-existent one.
func (r *resolver) calibrateMethodOracle(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath string,
	reqBudget *requestBudget,
) {
	if r.methodDone {
		return
	}
	r.methodDone = true

	reqBudget.inc()
	exist, errE := sendProbeFull(ctx, httpClient, bogusMethod, basePath)
	reqBudget.inc()
	missing, errM := sendProbeFull(ctx, httpClient, bogusMethod, basePath+utils.RandomString(14))
	if errE != nil || errM != nil {
		return
	}
	r.methodOK = exist.status == 405 && missing.status != 405
}

// isDirectory reports whether the given path segment is a directory, detected by
// a redirect to a trailing-slash location.
func (r *resolver) isDirectory(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath, seg string,
	reqBudget *requestBudget,
) bool {
	reqBudget.inc()
	got, err := sendProbeFull(ctx, httpClient, "GET", basePath+escapeSegment(seg))
	if err != nil {
		return false
	}
	if got.status != 301 && got.status != 302 {
		return false
	}
	loc := strings.ToLower(strings.TrimSpace(got.location))
	return strings.HasSuffix(loc, "/")
}

// classifyName flags filenames whose disclosure is security-sensitive.
func classifyName(full string) (sensitive bool, reason string) {
	l := strings.ToLower(full)
	switch {
	case strings.Contains(l, "web.config"), strings.Contains(l, "machine.config"),
		strings.Contains(l, "applicationhost.config"), strings.Contains(l, "connectionstring"),
		strings.Contains(l, "appsettings"), strings.HasSuffix(l, ".config"):
		return true, "config"
	case hasAnySuffix(l, ".bak", ".old", ".backup", ".swp", ".tmp", ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"):
		return true, "backup"
	case hasAnySuffix(l, ".cs", ".vb", ".asax", ".asa", ".cshtml", ".vbhtml", ".sln", ".csproj", ".vbproj"):
		return true, "source"
	case hasAnySuffix(l, ".mdf", ".mdb", ".ldf", ".sqlite", ".db", ".sql"):
		return true, "database"
	case hasAnySuffix(l, ".pfx", ".pem", ".key", ".crt", ".cer", ".p12"):
		return true, "secret"
	}
	return false, ""
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

func isResourceStatus(status int) bool {
	switch status {
	case 200, 206, 301, 302, 307, 308, 401, 403, 500:
		return true
	}
	return false
}

// escapeSegment escapes a single path segment (spaces as %20, dots preserved).
func escapeSegment(seg string) string {
	return url.PathEscape(seg)
}
