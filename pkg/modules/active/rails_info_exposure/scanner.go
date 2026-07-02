package rails_info_exposure

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// Module implements the Rails Info Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Rails Info Exposure module.
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
		ds: dedup.LazyDiskSet("rails_info_exposure"),
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

// ScanPerRequest probes the host for exposed Rails development and debug endpoints.
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

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Walk the web root plus any context-path prefixes of the observed URL so a
	// Rails app mounted under a sub-path (e.g. /app/rails/info/routes) is reached,
	// not just the root. Claim each (host, base) pair up front so a fully-deduped
	// request issues no traffic — including the soft-404 fingerprint.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, base := range bases {
		for _, p := range probes {
			if result := m.probeEndpoint(ctx, httpClient, scanCtx, p, base+p.path, fp); result != nil {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

// looksLikeRailsHealthCheck reports whether a /up response is the genuine Rails
// health page rendered by Rails::HealthController#show (Rails 7.1+):
//
//	<!DOCTYPE html><html><body style="background-color: #01d28e"></body></html>
//
// It is a tiny text/html page whose defining trait is a coloured <body> status
// banner (green when healthy). Requiring that exact shape stops the markerless /up
// probe from fingerprinting every framework that merely returns a small 200 for
// /up — a Node/Express geo endpoint answering {"country":...} JSON, a generic
// catch-all, a load-balancer "OK" — as a Rails app.
func looksLikeRailsHealthCheck(contentType, body string) bool {
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "text/html") {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "<body") && strings.Contains(lower, "background-color")
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-rails-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	p probe,
	probePath string,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probePath)
	if err != nil {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
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
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
			return nil
		}
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil
			}
		}
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	var matchedMarkers []string

	if len(p.markers) > 0 {
		// For probes with markers: require at least one marker match.
		matched := false
		for _, marker := range p.markers {
			if strings.Contains(body, marker) {
				matched = true
				matchedMarkers = append(matchedMarkers, marker)
			}
		}
		if !matched {
			return nil
		}
	} else {
		// For the /up probe (no markers): confirm the response is the genuine Rails
		// health page rendered by Rails::HealthController#show, not merely a small
		// 200. Accepting any small non-empty 200 mis-fingerprinted every app that
		// answers /up — a Node/Express geo endpoint returning {"country":...} JSON,
		// a catch-all, a load-balancer "OK" — as Rails (observed firing "firm" on an
		// X-Powered-By: Express host). looksLikeRailsHealthCheck demands the Rails
		// shape; the soft-404 check then rules out a host that wildcards that shape.
		ct := ""
		if resp.Response() != nil {
			ct = resp.Response().Header.Get("Content-Type")
		}
		if !looksLikeRailsHealthCheck(ct, body) {
			return nil
		}
		if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, status, []byte(body), "") {
			return nil
		}
	}

	// Sub-directory catch-all guard for marker-based probes: now that we probe
	// under context-path prefixes, drop the finding if a nonexistent sibling under
	// the same parent returns the same markers (a handler that 200s every child).
	// The markerless /up probe is already guarded by ConfirmNotSoft404 above.
	if len(p.markers) > 0 && modkit.SiblingServesAnyMarker(scanCtx, ctx, httpClient, probePath, p.markers) {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Rails Info Exposed: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"rails", "ruby", "information-disclosure"},
			Reference:   []string{"https://guides.rubyonrails.org/configuring.html"},
		},
	}
}
