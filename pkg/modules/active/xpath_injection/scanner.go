package xpath_injection

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// xpathErrorRe matches error strings emitted by XPath/XQuery engines when a
// syntax-breaking payload corrupts the expression. These are engine-specific — a
// SPA, a JSON API, or a static page never produces them — so a match that is
// absent from the baseline (and survives stripping the reflected payload) is a
// high-signal, technology-matched indicator. Sources: Java (javax.xml.xpath,
// Xalan/Saxon), .NET (System.Xml.XPath), libxml2 (php/python), MSXML.
var xpathErrorRe = regexp.MustCompile(`(?i)(` +
	`XPathException|javax\.xml\.xpath|org\.apache\.xpath|net\.sf\.saxon|` +
	`System\.Xml\.XPath|MS\.Internal\.Xml|XPathEvaluator|` +
	`Expression must evaluate to a node-set|` +
	`xmlXPathEval|xmlXPathCompOp|warning:\s*SimpleXMLElement::xpath|` +
	`Invalid (?:XPath )?expression|Invalid predicate|unexpected token in|` +
	`XPST0003|SXXP0003|A closing (?:bracket|quotation) .*expected|` +
	`Unknown error in XPath|xpath error|xpath syntax error` +
	`)`)

// errorBreakers are payload suffixes that corrupt the surrounding XPath
// expression, provoking an engine error when the value reaches an XPath query.
var errorBreakers = []string{`'`, `"`, `']`, `')`, `'|`}

// boolPair is one always-true / always-false payload pair. Two pairs with
// different operands are used so a confirmed injection must reproduce across
// independent values (multi-round), ruling out dynamic-content coincidence.
type boolPair struct {
	truthy string
	falsy  string
}

// stringBoolPairs break out of a single-quoted XPath string context; numericBoolPairs
// suit an unquoted numeric predicate.
var (
	stringBoolPairs = []boolPair{
		{truthy: `' or '1'='1`, falsy: `' and '1'='2`},
		{truthy: `' or '7'='7`, falsy: `' and '3'='4`},
	}
	numericBoolPairs = []boolPair{
		{truthy: ` or 1=1`, falsy: ` and 1=2`},
		{truthy: ` or 7=7`, falsy: ` and 3=4`},
	}
)

// stringInert / numericInert carry the OR keyword yet are logically FALSE (they
// OR in a contradiction, so the predicate collapses to the original clause). A
// genuine XPath oracle evaluates them as false — they render the false/baseline
// page, never the always-true page. An endpoint that instead renders the TRUE
// page for them is reacting to the mere presence of the `or` token (a WAF or
// keyword-matching differential), not to boolean truth, and the boolean leg would
// otherwise misread that keyword differential as an injection.
const (
	stringInert  = `' or '1'='2`
	numericInert = ` or 1=2`
)

// Module implements the XPath Injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new XPath Injection module.
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
		rhm: dedup.LazyDefaultRHM("xpath_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// VulnClass identifies this module's finding class for cross-module dedup.
func (m *Module) VulnClass() string { return "xpath" }

// ScanPerInsertionPoint tests a parameter for XPath injection. It fails closed on
// any target that shows no XPath-engine evidence: the error leg needs an XPath
// error string, and the boolean leg needs a reproducible true/false differential —
// neither of which a non-XPath endpoint (SPA, JSON API, static page) produces.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
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

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), fmt.Sprintf("%d", ip.Type())) {
			return nil, nil
		}
	}

	base := ip.BaseValue()

	// Baseline: prefer the captured response; otherwise fetch the endpoint with the
	// original value. A blocked/empty baseline is unusable — fail closed.
	baselineBody, blocked, ok := m.send(ctx, ip, httpClient, base)
	if !ok || blocked {
		return nil, nil
	}
	if bb := strings.TrimSpace(baselineBody); bb == "" {
		if ctx.Response() != nil {
			baselineBody = ctx.Response().BodyToString()
		}
	}

	// Leg 1: error-based (strongest signal).
	if res := m.scanErrorBased(ctx, ip, httpClient, urlx.String(), base, baselineBody); res != nil {
		return []*output.ResultEvent{res}, nil
	}

	// Leg 2: boolean oracle.
	if res := m.scanBoolean(ctx, ip, httpClient, urlx.String(), base); res != nil {
		return []*output.ResultEvent{res}, nil
	}

	return nil, nil
}

// scanErrorBased injects syntax breakers and reports when a response leaks an
// XPath engine error that is absent from the baseline and survives stripping the
// reflected payload — then re-confirms with a benign control value so a static
// error page (error present regardless of input) is rejected.
func (m *Module) scanErrorBased(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	target, base, baselineBody string,
) *output.ResultEvent {
	baseHasErr := xpathErrorRe.MatchString(baselineBody)

	for _, brk := range errorBreakers {
		value := base + brk
		body, blocked, ok := m.send(ctx, ip, httpClient, value)
		if !ok || blocked {
			continue
		}
		stripped := modkit.StripReflected(body, value)
		hit := xpathErrorRe.FindString(stripped)
		if hit == "" || baseHasErr {
			continue
		}
		// Negative control: a benign value must NOT leave the error present, else
		// it's a static error page, not injection.
		ctrlBody, ctrlBlocked, ctrlOK := m.send(ctx, ip, httpClient, base+"vig")
		if !ctrlOK || ctrlBlocked {
			continue
		}
		if xpathErrorRe.MatchString(modkit.StripReflected(ctrlBody, base+"vig")) {
			continue
		}

		return m.result(ctx, target, ip,
			fmt.Sprintf("A syntax-breaking payload (%q) in parameter %q leaked an XPath engine error (%q) that is absent from the baseline and from a benign control request, indicating the value is concatenated into an XPath/XQuery expression.", value, ip.Name(), hit),
			[]string{"payload=" + value, "xpath_error=" + hit})
	}
	return nil
}

// scanBoolean runs the boolean oracle: two independent always-true payloads must
// agree, two independent always-false payloads must agree, and the true and false
// responses must differ. Requiring agreement across different operands rules out
// dynamic-content noise; requiring a true/false difference rules out a
// non-injectable parameter (where all four responses are identical). A SPA / catch-
// all shell returns the same page for everything, so it fails this closed.
//
// Three additional gates defend the weakest, most FP-prone leg against differentials
// that are not XPath:
//
//   - Determinism: the endpoint must answer the ORIGINAL value the same way twice
//     on a stable 2xx. Many login/workflow endpoints instead flap between a 200 page
//     and a 302 redirect (rotating session tokens) independent of our input; on
//     those the "true/false differential" is that flapping, not injected logic.
//   - Status discipline: a real oracle returns 200 for BOTH branches (same page
//     shape, different content). A 200↔302/4xx/5xx split across branches is a status
//     flip (auth redirect, error page), not the query result reacting.
//   - Inert control: an OR-keyword-but-logically-false payload must NOT reproduce the
//     TRUE page. If it does, the endpoint keys off the `or` token (a WAF/keyword
//     differential), not boolean truth.
func (m *Module) scanBoolean(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	target, base string,
) *output.ResultEvent {
	pairs := stringBoolPairs
	inert := stringInert
	if infra.IsNumericValue(base) {
		pairs = numericBoolPairs
		inert = numericInert
	}

	// Boolean matrix: two independent always-true and always-false payloads. Every
	// probe must be a usable 2xx — a branch flipping to a 302/4xx/5xx is a status
	// artifact (auth redirect, error page), not the injected logic. Then require
	// operand agreement within each branch and a real true/false differential.
	t1, ok1 := m.sendUsable(ctx, ip, httpClient, base+pairs[0].truthy)
	t2, ok2 := m.sendUsable(ctx, ip, httpClient, base+pairs[1].truthy)
	f1, ok3 := m.sendUsable(ctx, ip, httpClient, base+pairs[0].falsy)
	f2, ok4 := m.sendUsable(ctx, ip, httpClient, base+pairs[1].falsy)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil
	}
	if !modkit.BodiesSimilar(t1, t2) || !modkit.BodiesSimilar(f1, f2) || modkit.BodiesSimilar(t1, f1) {
		return nil
	}

	// Determinism precondition (only worth paying once a clean differential exists):
	// the endpoint must answer the ORIGINAL value the same way twice on a stable 2xx.
	// Many login/workflow endpoints instead flap between a 200 page and a 302 redirect
	// (rotating session tokens) independent of our input; on those the differential
	// above is that flapping, not injected logic — fail closed.
	b1, bok1 := m.sendUsable(ctx, ip, httpClient, base)
	b2, bok2 := m.sendUsable(ctx, ip, httpClient, base)
	if !bok1 || !bok2 || !modkit.BodiesSimilar(b1, b2) {
		return nil
	}

	// Inert control: an OR-keyword-but-logically-false payload must render the
	// false/baseline page, never the TRUE page. If it reproduces the TRUE page, the
	// differential tracks the `or` keyword rather than boolean truth — reject. A
	// blocked/failed/non-2xx inert probe (sendUsable ok=false) proves nothing and is
	// ignored (that check fails open).
	if ib, iok := m.sendUsable(ctx, ip, httpClient, base+inert); iok && modkit.BodiesSimilar(ib, t1) {
		return nil
	}

	return m.result(ctx, target, ip,
		fmt.Sprintf("Parameter %q behaves as an XPath boolean oracle: two independent always-true payloads produced matching responses, two independent always-false payloads produced a different matching response, and the true/false responses differ — the injected boolean logic controls the query result.", ip.Name()),
		[]string{
			"true_payload=" + base + pairs[0].truthy,
			"false_payload=" + base + pairs[0].falsy,
		})
}

// sendStatus issues a request with value at the insertion point and returns the
// body, HTTP status code, whether it was a WAF/CDN block, and whether the request
// succeeded. The status lets the boolean leg enforce that a differential is a
// 200-vs-200 content difference rather than a status flip.
//
// The boolean leg sends with NoClustering so every probe is a genuine network
// round-trip. The 500ms request-cluster cache keys on raw request bytes, so
// without this the determinism precondition (the original value fetched twice)
// would compare a response against its own cached copy and never observe a
// flapping endpoint — the exact non-determinism the gate exists to reject.
func (m *Module) sendStatus(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	value string,
) (body string, status int, blocked bool, ok bool) {
	raw := ip.BuildRequest([]byte(value))
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return "", 0, false, false
	}
	defer resp.Close()
	if infra.IsBlockedResponse(resp) {
		return "", 0, true, true
	}
	sc := 0
	if resp.Response() != nil {
		sc = resp.Response().StatusCode
	}
	return resp.Body().String(), sc, false, true
}

// send issues a request with value at the insertion point and returns the body,
// whether it was a WAF/CDN block, and whether the request succeeded.
func (m *Module) send(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	value string,
) (body string, blocked bool, ok bool) {
	body, _, blocked, ok = m.sendStatus(ctx, ip, httpClient, value)
	return body, blocked, ok
}

// sendUsable sends value and reports the body plus whether the response is USABLE
// as a boolean-oracle branch: a non-blocked 2xx. A failed, WAF-blocked, or non-2xx
// (status-flip) response is not a content differential the injected logic could
// produce, so the boolean leg treats it as unusable.
func (m *Module) sendUsable(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	value string,
) (string, bool) {
	body, status, blocked, ok := m.sendStatus(ctx, ip, httpClient, value)
	return body, ok && !blocked && infra.Is2xx(status)
}

// result builds the finding for a confirmed XPath injection at ip.
func (m *Module) result(
	ctx *httpmsg.HttpRequestResponse,
	target string,
	ip httpmsg.InsertionPoint,
	desc string,
	extracted []string,
) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		URL:              target,
		Matched:          target,
		FuzzingParameter: ip.Name(),
		ExtractedResults: extracted,
		Request:          string(ctx.Request().Raw()),
		Info: output.Info{
			Name:        "XPath Injection",
			Description: desc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}
}
