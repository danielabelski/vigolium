package path_relative_stylesheet

import (
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

var (
	linkTagRe = regexp.MustCompile(`(?i)<link\b[^>]*>`)
	hrefRe    = regexp.MustCompile(`(?i)href\s*=\s*["']?([^"'\s>]+)`)
)

type fetched struct {
	status  int
	body    string
	ctype   string
	nosniff bool
	full    string
	raw     []byte
	ok      bool
}

// Module implements the path-relative stylesheet import (PRSSI) scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new PRSSI module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest, modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("path_relative_stylesheet"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess restricts to GET requests with a response (idempotent re-fetches).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	return strings.EqualFold(ctx.Request().Method(), "GET")
}

// ScanPerRequest confirms PRSSI with three gates: the page carries a path-relative
// stylesheet and omits nosniff; a path-info-confused URL serves the same page; and a
// genuinely nonexistent sibling does NOT (so a universal catch-all is excluded).
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	key := "GET|" + urlx.Host + "|" + urlx.Path
	if diskSet != nil && diskSet.IsSeen(key) {
		return nil, nil
	}

	origPath := urlx.Path
	if origPath == "" {
		origPath = "/"
	}

	// Baseline: a fresh fetch so headers (Content-Type / X-Content-Type-Options) are
	// authoritative.
	base, abort := m.get(ctx, httpClient, origPath, true)
	if abort || !base.ok || base.status != 200 || modkit.ClassifyContentType(base.ctype) != modkit.ContentClassHTML {
		return nil, nil
	}
	// Exploitability gate: nosniff defeats the CSS content-sniffing needed here.
	if base.nosniff {
		return nil, nil
	}
	if !hasPathRelativeStylesheet(base.body) {
		return nil, nil
	}

	// Path-info confusion: the same page must be served at a deeper URL.
	seg := "vigolium-prssi-" + strings.ToLower(utils.RandomString(8))
	confusedPath := strings.TrimRight(origPath, "/") + "/" + seg + "/"
	confused, abort := m.get(ctx, httpClient, confusedPath, true)
	if abort || !confused.ok || confused.status != 200 || !modkit.BodiesSimilar(base.body, confused.body) {
		return nil, nil
	}

	// Catch-all disproof: a genuinely nonexistent sibling must NOT return the page,
	// or the server serves this content for any path and the path-info signal is
	// meaningless.
	control, abort := m.get(ctx, httpClient, siblingPath(origPath, "vigolium-prssi-404-"+strings.ToLower(utils.RandomString(8))), false)
	if abort {
		return nil, nil
	}
	if control.ok && control.status == 200 && modkit.BodiesSimilar(base.body, control.body) {
		return nil, nil
	}

	target := urlx.Scheme + "://" + urlx.Host + confusedPath
	return []*output.ResultEvent{{
		URL:      target,
		Matched:  target,
		Request:  string(confused.raw),
		Response: confused.full,
		AdditionalEvidence: []string{
			output.BuildEvidence("baseline page (path-relative stylesheet, no nosniff)", string(base.raw), base.full),
		},
		ExtractedResults: []string{
			"path_relative_stylesheet=true",
			"nosniff=false",
			"confused_path=" + confusedPath,
		},
		Info: output.Info{
			Name:        ModuleName,
			Description: ModuleDesc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}}, nil
}

// get fetches path with a GET and returns a compact response view. When wantFull is
// false the full response string and raw request are not materialized — used for the
// catch-all control probe, which is judged only on status + body.
func (m *Module) get(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, path string, wantFull bool) (fetched, bool) {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return fetched{}, false
	}
	if raw, err = httpmsg.SetPath(raw, path); err != nil {
		return fetched{}, false
	}
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, execErr := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if execErr != nil {
		if errors.Is(execErr, hosterrors.ErrUnresponsiveHost) {
			return fetched{}, true
		}
		return fetched{}, false
	}
	defer resp.Close()
	r := resp.Response()
	if r == nil {
		return fetched{}, false
	}
	f := fetched{
		status:  r.StatusCode,
		body:    resp.Body().String(),
		ctype:   r.Header.Get("Content-Type"),
		nosniff: strings.Contains(strings.ToLower(r.Header.Get("X-Content-Type-Options")), "nosniff"),
		ok:      true,
	}
	if wantFull {
		f.full = resp.FullResponseString()
		f.raw = raw
	}
	return f, false
}

// siblingPath replaces the final path segment of p with name (a nonexistent sibling
// under the same directory).
func siblingPath(p, name string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "/" + name
	}
	return p[:i+1] + name
}

// hasPathRelativeStylesheet reports whether body links a stylesheet with a
// path-relative href (not root-relative, protocol-relative, or absolute).
func hasPathRelativeStylesheet(body string) bool {
	for _, tag := range linkTagRe.FindAllString(body, -1) {
		if !strings.Contains(strings.ToLower(tag), "stylesheet") {
			continue
		}
		mm := hrefRe.FindStringSubmatch(tag)
		if mm == nil {
			continue
		}
		if isPathRelative(strings.TrimSpace(mm[1])) {
			return true
		}
	}
	return false
}

// isPathRelative reports whether href resolves against the current path (so a deeper
// base URL changes where it points) rather than being absolute or root-relative.
func isPathRelative(href string) bool {
	if href == "" {
		return false
	}
	l := strings.ToLower(href)
	switch {
	case strings.HasPrefix(href, "/"), strings.HasPrefix(href, "#"):
		return false
	case strings.HasPrefix(l, "http://"), strings.HasPrefix(l, "https://"), strings.HasPrefix(l, "//"):
		return false
	case strings.HasPrefix(l, "data:"), strings.Contains(l, "://"):
		return false
	}
	return true
}
