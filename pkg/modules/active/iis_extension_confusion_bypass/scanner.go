package iis_extension_confusion_bypass

import (
	"fmt"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/iisgate"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// Module confirms IIS-specific request-parsing quirks (NTFS ADS source
// disclosure, trailing-dot and ::$INDEX_ALLOCATION access-control bypass).
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
	// limitCheckPerHost caps how many matching records (script-file or 401/403
	// responses) this per-request module acts on per host — a scanned-request
	// cap, not an HTTP probe budget.
	limitCheckPerHost int
}

// New creates a new IIS Extension Confusion Bypass module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds:                dedup.LazyDiskSet("iis_extension_confusion_bypass"),
		limitCheckPerHost: 20,
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false to use custom CanProcess logic.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess is a fast pre-filter requiring an IIS-looking response.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	return iisgate.RespLooksIIS(ctx.Response())
}

// ScanPerRequest dispatches to source disclosure (for executed script files) or
// access-control bypass (for 401/403 responses).
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	host := urlx.Hostname()
	if ctx.Response() == nil {
		return nil, nil
	}
	// Gate: passive detection AND active behavioral confirmation (a spoofed
	// Server header alone never passes). Cached per host across IIS modules.
	if !iisgate.IsIIS(ctx, scanCtx, host, httpClient) {
		return nil, nil
	}

	status := ctx.Response().StatusCode()
	path := urlx.EscapedPath()

	switch {
	case status == 200 && isScriptPath(path):
		if !m.markAndShouldContinue(urlx, scanCtx) {
			return nil, nil
		}
		if r := m.sourceDisclosure(ctx, httpClient, urlx, path); r != nil {
			return []*output.ResultEvent{r}, nil
		}
	case status == 401 || status == 403:
		if !m.markAndShouldContinue(urlx, scanCtx) {
			return nil, nil
		}
		if r := m.accessBypass(ctx, httpClient, urlx, path); r != nil {
			return []*output.ResultEvent{r}, nil
		}
	}
	return nil, nil
}

// sourceDisclosure attempts to read a script file's raw source via NTFS ::$DATA,
// confirming the response is genuine source (not the rendered page), reproducing
// on re-request, and not returned for an arbitrary decoy path.
func (m *Module) sourceDisclosure(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlx *urlutil.URL,
	path string,
) *output.ResultEvent {
	rendered := ""
	if b := ctx.Response().Body(); b != nil {
		rendered = string(b)
	}
	// If the executed page already exposes directives, ::$DATA gives no new
	// signal — bail to avoid ambiguity.
	if hasSourceMarkers(rendered) {
		return nil
	}

	for _, suffix := range sourceVectorSuffixes {
		vec := path + suffix

		// Round 1: the ADS request must return raw source distinct from the page.
		st, body, ok := m.probe(ctx, httpClient, vec)
		if !ok || st != 200 || !hasSourceMarkers(body) || modkit.BodiesSimilar(body, rendered) {
			continue
		}

		// Round 2: decoy negative — the same trick on a random script path must
		// NOT return source (rules out a server that streams source for anything).
		decoy := "/" + modkit.FreshCanary() + ".aspx" + suffix
		if dst, dbody, dok := m.probe(ctx, httpClient, decoy); dok && dst == 200 && hasSourceMarkers(dbody) {
			return nil
		}

		// Round 3: re-confirm determinism.
		st2, body2, ok2 := m.probe(ctx, httpClient, vec)
		if !ok2 || st2 != 200 || !hasSourceMarkers(body2) {
			continue
		}

		return m.buildFinding(urlx, vec,
			"IIS Script Source Disclosure via NTFS ::$DATA",
			fmt.Sprintf("The raw server-side source of `%s` was disclosed by appending the NTFS default data stream (`%s`), returning the unprocessed file instead of executing it.", path, suffix),
			body, []string{"source-disclosure", "ntfs-ads"})
	}
	return nil
}

// accessBypass attempts IIS-specific rewrites of a forbidden path and confirms
// the bypass reaches distinct real content, reproduces, and is not a catch-all.
func (m *Module) accessBypass(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlx *urlutil.URL,
	path string,
) *output.ResultEvent {
	for shape := 0; shape < numAccessShapes; shape++ {
		cand, label, ok := applyAccessShape(path, shape)
		if !ok {
			continue
		}

		// Round 1: the rewrite must now be allowed (200).
		st, body, ok := m.probe(ctx, httpClient, cand)
		if !ok || st != 200 {
			continue
		}
		if modkit.ResemblesObservedPage(ctx, body) {
			continue
		}

		// Round 2: decoy negative — the same shape on a random path must not also
		// yield the same 200 body (would indicate a catch-all, not a real bypass).
		decoyBase := "/" + modkit.FreshCanary()
		if strings.HasSuffix(path, "/") {
			decoyBase += "/"
		} else {
			decoyBase += pathExt(path)
		}
		if decoy, _, dok := applyAccessShape(decoyBase, shape); dok {
			if dst, dbody, dok2 := m.probe(ctx, httpClient, decoy); dok2 && dst == 200 && modkit.BodiesSimilar(body, dbody) {
				return nil
			}
		}

		// Round 3: re-confirm determinism.
		st2, body2, ok2 := m.probe(ctx, httpClient, cand)
		if !ok2 || st2 != 200 || !modkit.BodiesSimilar(body, body2) {
			continue
		}

		return m.buildFinding(urlx, cand,
			"IIS Access-Control Bypass via Path Parsing Quirk",
			fmt.Sprintf("A resource that returned %d when requested directly became reachable (200) using the IIS-specific `%s` rewrite, bypassing the path-based access control.", ctx.Response().StatusCode(), label),
			body, []string{"access-control", label})
	}
	return nil
}

// probe issues a GET to path (verbatim target) and returns status/body.
func (m *Module) probe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
) (int, string, bool) {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return 0, "", false
	}
	raw, err = httpmsg.SetPath(raw, path)
	if err != nil {
		return 0, "", false
	}
	return modkit.ExecuteRaw(httpClient, ctx.Service(), raw, http.Options{NoRedirects: true, NoClustering: true})
}

// buildFinding assembles a High-severity finding with an evidence snippet.
func (m *Module) buildFinding(urlx *urlutil.URL, candPath, name, desc, body string, tags []string) *output.ResultEvent {
	fullURL := urlx.Scheme + "://" + urlx.Host + candPath

	snippet := body
	if len(snippet) > 400 {
		snippet = snippet[:400]
	}
	desc += fmt.Sprintf("\n\n**Evidence snippet:**\n```\n%s\n```", snippet)

	allTags := append([]string{"iis", "aspnet"}, tags...)
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		URL:              fullURL,
		Matched:          fullURL,
		ExtractedResults: []string{candPath},
		Info: output.Info{
			Name:        name,
			Description: desc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        allTags,
			Reference: []string{
				"https://mll.sh/humiliating-iis-servers-for-fun-and-jail-time/",
				"https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf",
			},
		},
	}
}

func (m *Module) markAndShouldContinue(urlx *urlutil.URL, scanCtx *modkit.ScanContext) bool {
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet == nil {
		return true
	}
	_, shouldContinue := diskSet.IncrementAndCheck(urlx.Hostname(), m.limitCheckPerHost)
	return shouldContinue
}
