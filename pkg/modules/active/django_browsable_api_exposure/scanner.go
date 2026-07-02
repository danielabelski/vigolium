package django_browsable_api_exposure

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

var (
	// strongMarkers are Django-REST-Framework-specific tokens that appear only in
	// a genuine DRF browsable-API page (framework name, static asset path, the
	// browsable-api class). At least one MUST be present to report.
	strongMarkers = []string{"django-rest-framework", "rest_framework", "browsable-api"}
	// corroborators are generic layout tokens that DRF's template also uses but
	// which occur widely in unrelated themes/SPAs ("content-main", "api-breadcrumb").
	// They are recorded as supporting evidence only — NEVER a sole trigger. The
	// motivating false-positive class: the module re-requests the ORIGINAL page
	// with Accept: text/html, so any benign 200 HTML shell carrying a "content-main"
	// div would otherwise be reported as a Django browsable-API exposure.
	corroborators = []string{"api-breadcrumb", "content-main"}
	antiMarkers   = []string{"404 Not Found"}
)

// Module implements the Django Browsable API Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Django Browsable API Exposure module.
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
		ds: dedup.LazyDiskSet("django_browsable_api_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest probes the host for DRF browsable API exposure.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Probe 1: Re-request the original URL with Accept: text/html.
	if result := m.probeWithAcceptHTML(ctx, httpClient, "", "Original endpoint with Accept: text/html"); result != nil {
		results = append(results, result)
	}

	// Probe 2: Request /api/ with Accept: text/html.
	if result := m.probeWithAcceptHTML(ctx, httpClient, "/api/", "DRF API root"); result != nil {
		results = append(results, result)
	}

	return results, nil
}

func (m *Module) probeWithAcceptHTML(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	overridePath string,
	name string,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}

	if overridePath != "" {
		modifiedRaw, err = httpmsg.SetPath(modifiedRaw, overridePath)
		if err != nil {
			return nil
		}
	}

	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Accept", "text/html")
	if err != nil {
		return nil
	}

	// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") ||
			strings.Contains(strings.ToLower(location), "auth") {
			return nil
		}
	}

	body := resp.Body().String()

	for _, anti := range antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	// A DRF-specific anchor must be present; generic layout tokens alone are not
	// enough (they occur in unrelated pages the module re-fetches with Accept: html).
	var matchedMarkers []string
	for _, marker := range strongMarkers {
		if strings.Contains(body, marker) {
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if len(matchedMarkers) == 0 {
		return nil
	}
	// Record any generic layout tokens as supporting evidence only.
	for _, marker := range corroborators {
		if strings.Contains(body, marker) {
			matchedMarkers = append(matchedMarkers, marker)
		}
	}

	urlx, _ := ctx.URL()
	probePath := overridePath
	if probePath == "" {
		probePath = urlx.Path
	}
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Django Browsable API Exposure: %s", name),
			Description: "Django REST Framework browsable API is enabled in production, exposing interactive API documentation and schema details",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"python", "django", "drf", "browsable-api", "information-disclosure"},
			Reference:   []string{"https://www.django-rest-framework.org/topics/browsable-api/"},
		},
	}
}
