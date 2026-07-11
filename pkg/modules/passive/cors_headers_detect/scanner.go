package cors_headers_detect

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"go.uber.org/zap"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the CORS Headers Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CORS Headers Detect module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_cors_headers_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// reflectsCrossOrigin reports whether the response's Access-Control-Allow-Origin
// echoes the request's Origin header (proving dynamic reflection rather than a
// static allow-list entry) AND that reflected origin is cross-origin to the
// target host. A same-origin reflection, an absent Origin, or an ACAO that does
// not match the sent Origin is not a credentials exposure and must not be flagged.
func reflectsCrossOrigin(reqOrigin, acao, targetHost string) bool {
	reqOrigin = strings.TrimSpace(reqOrigin)
	if reqOrigin == "" || !strings.EqualFold(reqOrigin, strings.TrimSpace(acao)) {
		return false
	}
	o, err := url.Parse(reqOrigin)
	if err != nil || o.Hostname() == "" {
		return false
	}
	return !strings.EqualFold(o.Hostname(), targetHost)
}

// ScanPerRequest analyzes response for permissive CORS headers.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	acao := ctx.Response().Header("Access-Control-Allow-Origin")
	if acao == "" {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s%s", urlx.Host, urlx.Path, acao))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	acac := ctx.Response().Header("Access-Control-Allow-Credentials")

	var issues []string

	// Wildcard origin
	if acao == "*" {
		issues = append(issues, "Wildcard (*) Access-Control-Allow-Origin")
	}

	// Wildcard with credentials
	if acao == "*" && strings.EqualFold(acac, "true") {
		issues = append(issues, "Wildcard origin with Access-Control-Allow-Credentials: true")
	}

	// Null origin
	if strings.EqualFold(acao, "null") {
		issues = append(issues, "Null origin accepted in Access-Control-Allow-Origin")
	}

	// Credentials enabled alongside a specific (non-wildcard, non-null) origin is
	// only a real exposure when the server REFLECTS an arbitrary cross-origin
	// Origin back. A fixed allow-list entry — or a site echoing its OWN origin —
	// paired with credentials is the normal, safe pattern, so passively we require
	// the response to echo the request's Origin AND that origin to be cross-origin
	// to the target host. (The active cors_misconfiguration module probes with an
	// evil Origin and is what proves true reflection.) This drops the false
	// positive where a site reflects its own origin with credentials, e.g. a
	// Cloudflare RUM telemetry beacon whose ACAO is its own host.
	if strings.EqualFold(acac, "true") && acao != "*" && !strings.EqualFold(acao, "null") {
		if reflectsCrossOrigin(ctx.Request().Header("Origin"), acao, urlx.Hostname()) {
			issues = append(issues, fmt.Sprintf("Credentials enabled for reflected cross-origin: %s", acao))
		}
	}

	if len(issues) == 0 {
		return nil, nil
	}

	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	confidence := severity.Certain
	if strings.EqualFold(acao, "null") || reflectsCrossOrigin(ctx.Request().Header("Origin"), acao, urlx.Hostname()) {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		sev = severity.Low
		confidence = severity.Tentative
	}

	// Annotate record with semantic tags
	if scanCtx != nil && scanCtx.RemarksAnnotator != nil && scanCtx.RequestUUIDResolver != nil {
		uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(ctx.Request().ID())
		if uuid != "" {
			tags := []string{"has-cors"}
			if acao == "*" {
				tags = append(tags, "cors-wildcard")
			}
			if err := scanCtx.RemarksAnnotator.AppendRemarks(context.Background(), map[string][]string{uuid: tags}); err != nil {
				zap.L().Debug("cors_headers_detect: failed to annotate", zap.Error(err))
			}
		}
	}

	return []*output.ResultEvent{
		{
			Host:          urlx.Host,
			URL:           urlx.String(),
			Request:       string(ctx.Request().Raw()),
			RecordKind:    kind,
			EvidenceGrade: grade,
			DedupKey:      fmt.Sprintf("cors-passive|%s|%s|%s", ctx.Request().Method(), urlx.Host, urlx.Path),
			ExtractedResults: append([]string{
				fmt.Sprintf("ACAO: %s", acao),
				fmt.Sprintf("ACAC: %s", acac),
			}, issues...),
			Info: output.Info{
				Description: strings.Join(issues, "; "),
				Severity:    sev,
				Confidence:  confidence,
			},
		},
	}, nil
}
