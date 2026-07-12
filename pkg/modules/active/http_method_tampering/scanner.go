package http_method_tampering

import (
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// dangerousMethods are write methods that should not be blindly enabled.
var dangerousMethods = []string{"PUT", "DELETE", "PATCH", "MKCOL", "MOVE", "COPY"}

// methodOverrideHeaders are headers that can override the HTTP method at the server level.
var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
}

// Module implements the HTTP Method Tampering active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds                dedup.Lazy[dedup.DiskSet]
	limitCheckPerHost int
}

// New creates a new HTTP Method Tampering module.
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
		ds:                dedup.LazyDiskSet("http_method_tampering"),
		limitCheckPerHost: 15,
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests HTTP method tampering on the given request.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
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
	// Generic method discovery must not mutate a real resource. PUT, PATCH,
	// DELETE, MOVE, COPY, and POST-with-DELETE-override can all have irreversible
	// effects, and a 2xx response still would not prove what state changed. Limit
	// this module to an idempotent GET seed plus safe OPTIONS semantics.
	if ctx.Request() == nil || !strings.EqualFold(ctx.Request().Method(), "GET") ||
		ctx.Response() == nil || ctx.Response().StatusCode() < 200 || ctx.Response().StatusCode() >= 300 {
		return nil, nil
	}

	if !m.markAndShouldContinue(urlx, scanCtx) {
		return nil, nil
	}

	options, ok := m.fetchSafeMethodResponse(ctx, httpClient, "OPTIONS", "", "")
	if !ok {
		return nil, nil
	}
	var results []*output.ResultEvent
	if declared := declaredDangerousMethods(options.allow, options.corsAllow); len(declared) > 0 {
		results = append(results, safeMethodObservation(
			urlx,
			"Server Declares Write-Oriented HTTP Methods",
			"The OPTIONS response advertises write-oriented methods. This is capability metadata only; it does not show that an unauthenticated write succeeds or that any state changes.",
			"OPTIONS",
			options,
			[]string{"declared_methods=" + strings.Join(declared, ",")},
		))
	}

	getResponse, getOK := m.fetchSafeMethodResponse(ctx, httpClient, "GET", "", "")
	getReplay, replayOK := m.fetchSafeMethodResponse(ctx, httpClient, "GET", "", "")
	if !getOK || !replayOK || !safeResponsesSimilar(getResponse, getReplay) {
		return results, nil
	}
	for _, header := range methodOverrideHeaders {
		first, firstOK := m.fetchSafeMethodResponse(ctx, httpClient, "GET", header, "OPTIONS")
		second, secondOK := m.fetchSafeMethodResponse(ctx, httpClient, "GET", header, "OPTIONS")
		if !firstOK || !secondOK ||
			!safeResponsesSimilar(first, second) ||
			!safeResponsesSimilar(first, options) ||
			safeResponsesSimilar(first, getResponse) {
			continue
		}
		results = append(results, safeMethodObservation(
			urlx,
			"HTTP Method Override Mechanism Observed",
			"A GET carrying "+header+": OPTIONS reproduced the direct OPTIONS response twice and differed from the normal GET. This proves override capability only; no privileged or state-changing method was invoked.",
			header,
			first,
			[]string{"visible_method=GET", "override_header=" + header, "override_value=OPTIONS", "replay_count=2"},
		))
		break
	}
	return results, nil
}

type safeMethodResponse struct {
	status      int
	body        string
	contentType string
	allow       string
	corsAllow   string
	request     string
	response    string
}

func (m *Module) fetchSafeMethodResponse(ctx *httpmsg.HttpRequestResponse, client *http.Requester, method, header, value string) (safeMethodResponse, bool) {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
	if err != nil {
		return safeMethodResponse{}, false
	}
	if header != "" {
		raw, err = httpmsg.AddOrReplaceHeader(raw, header, value)
		if err != nil {
			return safeMethodResponse{}, false
		}
	}
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil || resp == nil || resp.Response() == nil {
		if resp != nil {
			resp.Close()
		}
		return safeMethodResponse{}, false
	}
	defer resp.Close()
	if infra.IsBlockedResponse(resp) || resp.Response().StatusCode >= 500 {
		return safeMethodResponse{}, false
	}
	return safeMethodResponse{
		status:      resp.Response().StatusCode,
		body:        resp.BodyString(),
		contentType: resp.Response().Header.Get("Content-Type"),
		allow:       resp.Response().Header.Get("Allow"),
		corsAllow:   resp.Response().Header.Get("Access-Control-Allow-Methods"),
		request:     string(raw),
		response:    resp.FullResponseString(),
	}, true
}

func declaredDangerousMethods(values ...string) []string {
	wanted := make(map[string]bool, len(dangerousMethods))
	for _, method := range dangerousMethods {
		wanted[method] = true
	}
	seen := make(map[string]bool)
	var declared []string
	for _, value := range values {
		for _, token := range strings.FieldsFunc(strings.ToUpper(value), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if wanted[token] && !seen[token] {
				seen[token] = true
				declared = append(declared, token)
			}
		}
	}
	return declared
}

func safeResponsesSimilar(left, right safeMethodResponse) bool {
	if left.status != right.status || !strings.EqualFold(strings.TrimSpace(strings.Split(left.contentType, ";")[0]), strings.TrimSpace(strings.Split(right.contentType, ";")[0])) {
		return false
	}
	if left.body == "" || right.body == "" {
		return left.body == right.body
	}
	leftSig := modkit.NewResponseSignature(left.status, left.body, "OPTIONS")
	rightSig := modkit.NewResponseSignature(right.status, right.body, "OPTIONS")
	return modkit.RatioSimilar(leftSig, rightSig)
}

func safeMethodObservation(urlx *urlutil.URL, name, description, fuzzingParameter string, response safeMethodResponse, extracted []string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		Host:             urlx.Host,
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          response.request,
		Response:         response.response,
		FuzzingParameter: fuzzingParameter,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        name,
			Description: description,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
		Metadata: map[string]any{"state_change_observed": false, "authorization_bypass_observed": false, "safe_probe_only": true},
	}
}

// isSuccessfulMethod checks if a response indicates the method was accepted.
func isSuccessfulMethod(statusCode int, body string) bool {
	if statusCode < 200 || statusCode >= 300 {
		return false
	}

	// Filter out common false positives
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "method not allowed") ||
		strings.Contains(bodyLower, "not supported") ||
		strings.Contains(bodyLower, "/login") ||
		strings.Contains(bodyLower, "/signin") ||
		// Framework soft-errors: a 200 that is actually a session/CSRF/validation
		// rejection, not a performed action. Salesforce Aura answers ANY verb
		// (including DELETE) with an aura:invalidSession / exceptionEvent event at
		// HTTP 200 — the action never ran, so this is not a "successful" method.
		strings.Contains(bodyLower, "aura:invalidsession") ||
		strings.Contains(bodyLower, "\"exceptionevent\"") {
		return false
	}

	// Require meaningful body (not just empty 200)
	if len(body) < 50 {
		return false
	}

	return true
}

// markAndShouldContinue limits checks per host.
func (m *Module) markAndShouldContinue(urlx *urlutil.URL, scanCtx *modkit.ScanContext) bool {
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet == nil {
		return true
	}
	host := urlx.Hostname()
	_, shouldContinue := diskSet.IncrementAndCheck(host, m.limitCheckPerHost)
	return shouldContinue
}
