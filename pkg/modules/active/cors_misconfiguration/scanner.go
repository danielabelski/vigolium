package cors_misconfiguration

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// corsProbe defines a single CORS test case.
type corsProbe struct {
	name       string
	origin     string              // literal origin to send, or "" if originFunc is used
	originFunc func(string) string // computes origin from target host (for subdomain bypass)
	check      func(acao, acac string) bool
	// canaryOrigin, when set, marks a reflection-class probe (the server echoes
	// the sent origin verbatim in ACAO). It builds a fresh, randomized origin
	// that still satisfies the probe's (broken) matching rule, so the strict
	// confirmation can prove the server reflects an attacker-chosen origin it
	// could not have had in any static allowlist. When nil, the signal is a
	// fixed value (null / wildcard) and confirmation falls back to a
	// reproducibility check instead.
	canaryOrigin func(host, canary string) string
	// conditionalControl means exploitation additionally requires control of a
	// target-owned origin (for example a subdomain or alternate port).
	conditionalControl bool
	// browserRejected marks configurations browsers refuse to expose, such as
	// wildcard ACAO combined with credentials.
	browserRejected bool
	sev             severity.Severity
	desc            string
}

var probes = []corsProbe{
	{
		name:   "Reflected Origin",
		origin: "https://evil.example.com",
		check: func(acao, _ string) bool {
			return acao == "https://evil.example.com"
		},
		canaryOrigin: func(_, canary string) string { return "https://" + canary + ".example.com" },
		sev:          severity.Low,
		desc:         "The server reflects arbitrary Origin values in Access-Control-Allow-Origin, allowing any site to read cross-origin responses.",
	},
	{
		name:   "Null Origin",
		origin: "null",
		check: func(acao, _ string) bool {
			return acao == "null"
		},
		sev:  severity.Low,
		desc: "The server allows the null origin, which can be exploited via sandboxed iframes or redirects to perform cross-origin requests.",
	},
	{
		name:   "Wildcard with Credentials",
		origin: "https://example.com",
		check: func(acao, acac string) bool {
			return acao == "*" && strings.EqualFold(acac, "true")
		},
		sev:             severity.Low,
		browserRejected: true,
		desc:            "The server sets Access-Control-Allow-Origin to wildcard (*) while also allowing credentials, which is a misconfiguration that browsers should reject but may indicate insecure CORS logic.",
	},
	{
		name: "Subdomain Bypass",
		originFunc: func(host string) string {
			return "https://evil." + host
		},
		check: func(acao, _ string) bool {
			// acao must match the injected origin; checked by caller with the actual sent origin
			return acao != ""
		},
		canaryOrigin:       func(host, canary string) string { return "https://" + canary + "." + host },
		conditionalControl: true,
		sev:                severity.Low,
		desc:               "The server trusts subdomains of the target host as allowed origins. An attacker controlling any subdomain (e.g. via subdomain takeover) can read cross-origin responses.",
	},
	{
		name: "Prefix Bypass",
		originFunc: func(host string) string {
			return "https://evil-" + host
		},
		check: func(acao, _ string) bool {
			return acao != ""
		},
		canaryOrigin: func(host, canary string) string { return "https://" + canary + "-" + host },
		sev:          severity.Low,
		desc:         "The server uses incorrect prefix matching for origin validation. An attacker can register a domain prefixed with the target host to bypass CORS restrictions.",
	},
	{
		name: "Suffix Bypass",
		originFunc: func(host string) string {
			return "https://" + host + ".evil.com"
		},
		check: func(acao, _ string) bool {
			return acao != ""
		},
		canaryOrigin: func(host, canary string) string { return "https://" + host + "." + canary + ".com" },
		sev:          severity.Low,
		desc:         "The server uses incorrect suffix matching for origin validation. An attacker can use a subdomain of their own domain that ends with the target hostname to bypass CORS restrictions.",
	},
	{
		name: "Port-Based Bypass",
		originFunc: func(host string) string {
			return "https://" + host + ":8443"
		},
		check: func(acao, _ string) bool {
			return acao != ""
		},
		sev:                severity.Low,
		conditionalControl: true,
		desc:               "The server trusts origins on non-standard ports of the target host, which may be exploitable if other services run on those ports.",
	},
	{
		name:   "HTTP Scheme Confusion",
		origin: "http://evil.example.com",
		check: func(acao, _ string) bool {
			return acao == "http://evil.example.com"
		},
		canaryOrigin: func(_, canary string) string { return "http://" + canary + ".example.com" },
		sev:          severity.Low,
		desc:         "The server reflects HTTP-scheme origins in ACAO, enabling mixed-content cross-origin attacks.",
	},
}

// Module implements the CORS misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CORS Misconfiguration module.
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
		ds: dedup.LazyDiskSet("cors_misconfiguration"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess
// that does not include the base URL/media/method checks.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response (to confirm the host is live).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	// Require a response to confirm the host is reachable
	if ctx.Response() == nil {
		return false
	}
	return true
}

// ScanPerRequest runs CORS probes once per route and method because CORS policy
// commonly differs across API endpoints on the same origin.
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

	// Dedup by route + method + identity, not host. Personalized endpoints may
	// expose a different CORS policy after authentication.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	semanticKey := strings.ToUpper(ctx.Request().Method()) + "|" + host + "|" + urlx.Path + "|" + ctx.Request().IdentityFingerprint()
	if diskSet != nil && diskSet.IsSeen(semanticKey) {
		return nil, nil
	}

	var best *output.ResultEvent

	for _, probe := range probes {
		// Determine probe origin
		origin := probe.origin
		if probe.originFunc != nil {
			origin = probe.originFunc(host)
		}

		result, err := m.runProbe(ctx, httpClient, scanCtx, probe, origin)
		if err != nil {
			continue
		}
		if result != nil {
			result.DedupKey = "cors-policy|" + semanticKey
			if best == nil || corsResultRank(result) > corsResultRank(best) {
				best = result
			} else {
				best.ExtractedResults = append(best.ExtractedResults, "Also matched: "+probe.name)
			}
		}
	}

	if best == nil {
		return nil, nil
	}
	return []*output.ResultEvent{best}, nil
}

// ScanPerHost retains direct-call compatibility for existing integrations and
// tests; registry dispatch uses ScanPerRequest via the declared scope.
func (m *Module) ScanPerHost(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	return m.ScanPerRequest(ctx, httpClient, scanCtx)
}

func corsResultRank(result *output.ResultEvent) int {
	kindRank := map[output.RecordKind]int{
		output.RecordKindObservation: 0,
		output.RecordKindCandidate:   100,
		output.RecordKindFinding:     200,
	}[result.EffectiveRecordKind()]
	return kindRank + int(result.Info.Severity)
}

type corsExchange struct {
	status      int
	acao        string
	acac        string
	contentType string
	body        string
	rawRequest  []byte
	rawResponse string
}

// corsHeaders sends a request carrying origin. When stripCredentials is true,
// Cookie and Authorization are removed to create an unauthenticated control.
func corsHeaders(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, origin string, stripCredentials bool) (corsExchange, bool) {
	raw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), "Origin", origin)
	if err != nil {
		return corsExchange{}, false
	}
	if stripCredentials {
		raw, _ = httpmsg.RemoveHeader(raw, "Cookie")
		raw, _ = httpmsg.RemoveHeader(raw, "Authorization")
	}
	// AddOrReplaceHeader produces well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return corsExchange{rawRequest: raw}, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return corsExchange{rawRequest: raw}, false
	}
	return corsExchange{
		status:      resp.Response().StatusCode,
		acao:        resp.Response().Header.Get("Access-Control-Allow-Origin"),
		acac:        resp.Response().Header.Get("Access-Control-Allow-Credentials"),
		contentType: resp.Response().Header.Get("Content-Type"),
		body:        resp.Body().String(),
		rawRequest:  raw,
		rawResponse: resp.FullResponseString(),
	}, true
}

func simpleCredentialedCORSRequest(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Request().Header("Cookie") == "" || ctx.Request().Header("Authorization") != "" {
		return false
	}
	switch strings.ToUpper(ctx.Request().Method()) {
	case "GET", "HEAD":
	case "POST":
		ct := strings.ToLower(ctx.Request().Header("Content-Type"))
		if i := strings.IndexByte(ct, ';'); i >= 0 {
			ct = strings.TrimSpace(ct[:i])
		}
		if ct != "" && ct != "application/x-www-form-urlencoded" && ct != "multipart/form-data" && ct != "text/plain" {
			return false
		}
	default:
		return false
	}

	// This module does not exercise preflight yet. Do not claim a confirmed
	// browser exploit when the captured request depends on a non-safelisted
	// application header that an attacker origin cannot send directly.
	for _, header := range ctx.Request().Headers() {
		name := strings.ToLower(header.Name)
		switch name {
		case "accept", "accept-language", "content-language", "content-type",
			"host", "cookie", "user-agent", "referer", "origin", "connection",
			"accept-encoding", "content-length":
			continue
		default:
			if strings.HasPrefix(name, "sec-") {
				continue
			}
			return false
		}
	}
	return true
}

func browserSendableSessionCookie(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) (bool, string) {
	if ctx == nil || ctx.Request() == nil || scanCtx == nil {
		return false, "cookie policy unavailable"
	}
	scanCtx.ObserveResponseCookies(ctx)
	policies := scanCtx.RequestCookiePolicies(ctx)
	if len(policies) == 0 {
		return false, "session cookie attributes were not observed"
	}
	for _, policy := range policies {
		if !modkit.LikelySessionCookie(policy.Name) || policy.Partitioned {
			continue
		}
		if policy.Secure && policy.SameSite == "none" {
			return true, "SameSite=None; Secure session cookie can accompany a cross-site fetch"
		}
	}
	return false, "no observed session cookie is browser-sendable on a cross-site fetch"
}

func confirmCredentialedCORSExposure(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext, origin string, attack corsExchange) (bool, string, string) {
	if !simpleCredentialedCORSRequest(ctx) || !strings.EqualFold(attack.acac, "true") || len(strings.TrimSpace(attack.body)) < 16 {
		return false, "", "request is not a demonstrated simple credentialed CORS request"
	}
	credentialSendable, credentialReason := browserSendableSessionCookie(ctx, scanCtx)
	if !credentialSendable {
		return false, "", credentialReason
	}
	control, ok := corsHeaders(ctx, httpClient, origin, true)
	if !ok {
		return false, "", "unauthenticated control request failed"
	}
	evidence := output.BuildEvidence("unauthenticated-control", string(control.rawRequest), control.rawResponse)
	if control.status == 401 || control.status == 403 || control.status != attack.status {
		return true, evidence, credentialReason
	}
	if !modkit.BodiesSimilar(attack.body, control.body) {
		return true, evidence, credentialReason
	}
	return false, evidence, credentialReason
}

// runProbe executes a single CORS probe and returns a result if the check passes
// AND survives strict confirmation: the matched response must be a real (2xx)
// response, and the permissive ACAO must be confirmed either by a fresh-canary
// reflection (for reflection-class probes) or by a reproducibility re-check (for
// fixed-value probes). This drops error-page reflections and transient/jittery
// proxy headers — the dominant single-header false positives.
func (m *Module) runProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	probe corsProbe,
	origin string,
) (*output.ResultEvent, error) {
	attack, ok := corsHeaders(ctx, httpClient, origin, false)
	if !ok {
		return nil, nil
	}

	// For subdomain bypass, the check function needs the actual sent origin
	passes := false
	if probe.originFunc != nil {
		// Subdomain bypass: ACAO must exactly match the sent evil origin
		passes = attack.acao == origin
	} else {
		passes = probe.check(attack.acao, attack.acac)
	}

	if !passes {
		return nil, nil
	}

	// Status gate: a permissive ACAO on a non-2xx error/redirect response is not
	// a usable cross-origin read; drop it.
	if attack.status < 200 || attack.status >= 300 {
		return nil, nil
	}

	// Strict confirmation.
	signalConfirmed := true
	if probe.canaryOrigin != nil {
		// Reflection-class: the server must echo a freshly-randomized origin that
		// still satisfies the probe's rule, proving it reflects an attacker-chosen
		// origin rather than matching a fixed allowlist. Fail OPEN on an
		// inconclusive fetch error (already matched once); drop only on a clean
		// non-reflection.
		host := ctx.Service().Host()
		confirmed, err := modkit.ConfirmReflection(2, func(canary string) (bool, error) {
			o := probe.canaryOrigin(host, canary)
			exchange, fok := corsHeaders(ctx, httpClient, o, false)
			if !fok {
				return false, fmt.Errorf("cors confirm fetch failed")
			}
			return exchange.status >= 200 && exchange.status < 300 && exchange.acao == o, nil
		})
		if err == nil && !confirmed {
			return nil, nil
		}
		signalConfirmed = err == nil && confirmed
	} else {
		// Fixed-value (null / wildcard+creds): re-issue the same origin and require
		// the signal to reproduce identically. Drop only on a clean, completed
		// re-check that no longer matches.
		if second, ok2 := corsHeaders(ctx, httpClient, origin, false); ok2 {
			reproduces := second.status >= 200 && second.status < 300 && second.acao == attack.acao && second.acac == attack.acac
			if !reproduces {
				return nil, nil
			}
		} else {
			signalConfirmed = false
		}
	}

	target := ctx.Target()
	kind := output.RecordKindCandidate
	grade := output.EvidenceGradeCandidate
	sev := probe.sev
	confidence := severity.Tentative
	description := probe.desc
	var additionalEvidence []string
	impactConfirmed := false
	credentialReason := ""
	controlEvidence := ""

	switch {
	case probe.browserRejected:
		kind = output.RecordKindObservation
		grade = output.EvidenceGradeObservation
		sev = severity.Info
		confidence = severity.Certain
		description += " Browsers reject credentialed reads when ACAO is wildcard, so this is configuration posture rather than an exploitable credentialed exposure."
	case probe.conditionalControl:
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		confidence = severity.Tentative
		description += " Exploitation remains conditional on attacker control of the trusted target-owned origin."
	case signalConfirmed:
		grade = output.EvidenceGradeDifferential
		confidence = severity.Firm
		impactConfirmed, controlEvidence, credentialReason = confirmCredentialedCORSExposure(ctx, httpClient, scanCtx, origin, attack)
		if controlEvidence != "" {
			additionalEvidence = append(additionalEvidence, controlEvidence)
		}
		if impactConfirmed {
			kind = output.RecordKindFinding
			grade = output.EvidenceGradeBypass
			sev = severity.Medium
			description += " A credentialed response differed from the unauthenticated control, proving cross-origin access to protected content."
		} else {
			description += " Origin handling reproduced, but protected credentialed content was not demonstrated."
		}
	default:
		description += " The initial signal could not be reproduced because confirmation was inconclusive."
	}

	return &output.ResultEvent{
		URL:                target,
		Matched:            target,
		Request:            string(attack.rawRequest),
		Response:           attack.rawResponse,
		RecordKind:         kind,
		EvidenceGrade:      grade,
		AdditionalEvidence: additionalEvidence,
		ExtractedResults: []string{
			fmt.Sprintf("ACAO: %s", attack.acao),
			fmt.Sprintf("ACAC: %s", attack.acac),
			fmt.Sprintf("Probe: %s", probe.name),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("CORS Misconfiguration: %s", probe.name),
			Description: description,
			Severity:    sev,
			Confidence:  confidence,
			Reference:   []string{"https://portswigger.net/web-security/cors"},
		},
		Metadata: map[string]any{
			"signal_confirmed":    signalConfirmed,
			"impact_confirmed":    impactConfirmed,
			"credential_reason":   credentialReason,
			"conditional_control": probe.conditionalControl,
			"browser_rejected":    probe.browserRejected,
		},
	}, nil
}
