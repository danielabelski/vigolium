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

// boolPair is one always-true / always-false payload pair. THREE pairs with
// different operands are used so a confirmed injection must reproduce across three
// independent values, ruling out dynamic-content coincidence: a per-request
// changing body (a CDN challenge, a rotating token page) will not line three
// distinct always-true operands into one cluster and three distinct always-false
// operands into another by chance.
type boolPair struct {
	truthy string
	falsy  string
}

// stringBoolPairs break out of a single-quoted XPath string context; numericBoolPairs
// suit an unquoted numeric predicate. Each pair uses a distinct operand so agreement
// within a branch is agreement across independent values, not a repeated payload.
var (
	stringBoolPairs = []boolPair{
		{truthy: `' or '1'='1`, falsy: `' and '1'='2`},
		{truthy: `' or '7'='7`, falsy: `' and '3'='4`},
		{truthy: `' or '9'='9`, falsy: `' and '8'='7`},
	}
	numericBoolPairs = []boolPair{
		{truthy: ` or 1=1`, falsy: ` and 1=2`},
		{truthy: ` or 7=7`, falsy: ` and 3=4`},
		{truthy: ` or 9=9`, falsy: ` and 8=7`},
	}
)

// inertControls are payloads that carry an XPath boolean keyword yet are logically
// INERT — they leave the original predicate's truth value unchanged, so a genuine
// oracle renders the false/baseline page for them, NEVER the always-true page:
//
//   - OR-false (' or '1'='2): ORs in a contradiction → predicate collapses to the
//     original clause.
//   - AND-true (' and '1'='1): ANDs in a tautology → predicate collapses to the
//     original clause.
//
// They probe opposite keywords (`or` vs `and`) with opposite logic, yet must reach
// the same non-true outcome. An endpoint that renders the TRUE page for EITHER is
// reacting to the mere presence of the keyword (a WAF or keyword-matching
// differential), not to boolean truth — the boolean leg would otherwise misread that
// keyword differential as an injection. Requiring BOTH keywords to stay non-true
// gives symmetric coverage that a single OR-only control missed.
var (
	stringInertControls  = []string{`' or '1'='2`, `' and '1'='1`}
	numericInertControls = []string{` or 1=2`, ` and 1=1`}
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

	// A fixed browser request header (Accept-Language, User-Agent, Accept, ...) is
	// attacker-settable but never an XPath sink — no application concatenates it into
	// an XPath expression. On a CDN/challenge endpoint its value is reflected into a
	// per-request opaque body that fools the boolean oracle (the evr-kr.roche.com
	// Accept-Language /cdn-cgi false positive). Skip standard request headers.
	if ip.Type() == httpmsg.INS_HEADER && infra.IsStandardRequestHeader(ip.Name()) {
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

	// An XPath backend renders text/markup; an opaque high-entropy body (a compressed
	// or encrypted CDN/challenge blob) is not an XPath surface, and its per-request
	// content churn is exactly what fools the boolean oracle. Fail closed on it.
	if infra.LooksOpaqueBody(baselineBody) {
		return nil, nil
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

// scanBoolean runs the boolean oracle. To be believed, the parameter must behave
// like a real XPath boolean predicate under FIVE independent confirmations, all of
// which a non-XPath differential (dynamic content, a keyword-matching WAF, a status
// flip) fails:
//
//   - Multi-operand agreement: THREE independent always-true payloads must all land
//     on one page and THREE independent always-false payloads on another. Three
//     distinct operands clustering by truth value (not by payload) is the signature
//     of boolean evaluation; per-request dynamic content will not align three
//     different always-true values into one cluster and three different always-false
//     values into another by chance.
//   - True/false differential: the true and false clusters must differ — a catch-all
//     SPA/shell that returns one page for everything fails this closed.
//   - Status discipline: every probe must be a usable 2xx (via sendUsable). A branch
//     flipping to a 302/4xx/5xx is a status artifact (auth redirect, error page), not
//     the query result reacting.
//   - Determinism: the endpoint must answer the ORIGINAL value the same way twice on
//     a stable 2xx, ruling out endpoints that flap between pages independent of input.
//   - Symmetric inert controls: an OR-keyword-but-false payload AND an
//     AND-keyword-but-true payload must each render a NON-true page. Either one
//     reproducing the true page means the endpoint keys off the keyword (WAF/keyword
//     differential), not boolean truth. Testing both `or` and `and` keywords catches
//     a keyword reaction on either token, which the former single OR-only control let
//     through.
func (m *Module) scanBoolean(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	target, base string,
) *output.ResultEvent {
	pairs := stringBoolPairs
	inertControls := stringInertControls
	if infra.IsNumericValue(base) {
		pairs = numericBoolPairs
		inertControls = numericInertControls
	}

	// Boolean matrix: three independent always-true and three always-false payloads.
	// Every probe must be a usable 2xx; then require agreement within each branch and
	// a real true/false differential.
	trueBodies := make([]string, 0, len(pairs))
	falseBodies := make([]string, 0, len(pairs))
	for _, p := range pairs {
		tb, tok := m.sendUsable(ctx, ip, httpClient, base+p.truthy)
		if !tok {
			return nil
		}
		trueBodies = append(trueBodies, tb)
	}
	for _, p := range pairs {
		fb, fok := m.sendUsable(ctx, ip, httpClient, base+p.falsy)
		if !fok {
			return nil
		}
		falseBodies = append(falseBodies, fb)
	}
	// Each branch must be internally consistent across its independent operands, and
	// the two branches must genuinely differ.
	if !allBodiesSimilar(trueBodies) || !allBodiesSimilar(falseBodies) {
		return nil
	}
	if modkit.BodiesSimilar(trueBodies[0], falseBodies[0]) {
		return nil
	}
	truePage := trueBodies[0]

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

	// Symmetric inert controls: each logically-inert payload (OR-false, AND-true) must
	// render a NON-true page. If a usable inert probe reproduces the TRUE page, the
	// differential tracks the keyword rather than boolean truth — reject. A
	// blocked/failed/non-2xx inert probe (ok=false) proves nothing and is ignored
	// (fails open, so a transient block on a control cannot manufacture a rejection).
	for _, inert := range inertControls {
		if ib, iok := m.sendUsable(ctx, ip, httpClient, base+inert); iok && modkit.BodiesSimilar(ib, truePage) {
			return nil
		}
	}

	return m.result(ctx, target, ip,
		fmt.Sprintf("Parameter %q behaves as an XPath boolean oracle: three independent always-true payloads produced matching responses, three independent always-false payloads produced a different matching response, the true/false responses differ, and two symmetric inert controls (OR-false, AND-true) did not reproduce the true page — the injected boolean logic controls the query result.", ip.Name()),
		[]string{
			"true_payload=" + base + pairs[0].truthy,
			"false_payload=" + base + pairs[0].falsy,
		})
}

// allBodiesSimilar reports whether every body in bodies is textually similar to the
// first (so the whole slice forms one cluster). An empty or single-element slice is
// trivially similar. The first body's signature is built once and reused across the
// comparisons.
func allBodiesSimilar(bodies []string) bool {
	if len(bodies) < 2 {
		return true
	}
	sig := modkit.BodySignature(bodies[0])
	for _, b := range bodies[1:] {
		if !modkit.BodiesSimilarSig(sig, b) {
			return false
		}
	}
	return true
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
