package ws_injection

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

// wsParamNames contains parameter names commonly associated with WebSocket message processing.
var wsParamNames = map[string]bool{
	"message":   true,
	"msg":       true,
	"data":      true,
	"text":      true,
	"chat":      true,
	"payload":   true,
	"content":   true,
	"body":      true,
	"input":     true,
	"cmd":       true,
	"command":   true,
	"query":     true,
	"ws":        true,
	"websocket": true,
}

type injectionTest struct {
	payload  string
	category string
	// patterns to look for in the response body (case-insensitive)
	patterns []string
	// requireConsumed flags the probe only when the literal payload is ABSENT
	// from the response — i.e. it was evaluated, not reflected verbatim. Used for
	// the template-injection probes whose bare result marker ("49") is otherwise
	// far too weak to stand on its own.
	requireConsumed bool
}

var injectionTests = []injectionTest{
	// XSS payloads - check for unencoded reflection
	{
		payload:  `<img src=x onerror=alert(1)>`,
		category: "XSS",
		patterns: []string{`<img src=x onerror=alert(1)>`},
	},
	{
		payload:  `"><script>alert(1)</script>`,
		category: "XSS",
		patterns: []string{`"><script>alert(1)</script>`},
	},
	// SQLi payloads - check for SQL error messages
	{
		payload:  `' OR '1'='1`,
		category: "SQL Injection",
		patterns: []string{
			"syntax error",
			"mysql",
			"ora-",
			"postgresql",
			"sqlite",
			"unclosed quotation mark",
			"quoted string not properly terminated",
			"sql syntax",
			"microsoft sql",
		},
	},
	{
		payload:  `1; DROP TABLE--`,
		category: "SQL Injection",
		patterns: []string{
			"syntax error",
			"mysql",
			"ora-",
			"postgresql",
			"sqlite",
			"unclosed quotation mark",
			"sql syntax",
			"microsoft sql",
		},
	},
	{
		payload:  `' UNION SELECT NULL--`,
		category: "SQL Injection",
		patterns: []string{
			"syntax error",
			"mysql",
			"ora-",
			"postgresql",
			"sqlite",
			"union select",
			"sql syntax",
			"microsoft sql",
		},
	},
	// Command injection payloads
	{
		payload:  `; id`,
		category: "Command Injection",
		patterns: []string{"uid=", "gid="},
	},
	{
		payload:  `| cat /etc/passwd`,
		category: "Command Injection",
		patterns: []string{"root:", "/bin/bash", "/bin/sh"},
	},
	{
		payload:  "`id`",
		category: "Command Injection",
		patterns: []string{"uid=", "gid="},
	},
	// Template injection payloads — only count if "49" appears AND the literal
	// "{{7*7}}"/"${7*7}" did NOT survive in the body (proving evaluation).
	{
		payload:         `{{7*7}}`,
		category:        "Template Injection",
		patterns:        []string{"49"},
		requireConsumed: true,
	},
	{
		payload:         `${7*7}`,
		category:        "Template Injection",
		patterns:        []string{"49"},
		requireConsumed: true,
	},
}

// Module implements an active scanner for WebSocket injection vulnerabilities.
type Module struct {
	modkit.BaseActiveModule
	ds  dedup.Lazy[dedup.DiskSet]
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new WebSocket Injection scanner module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		ds:  dedup.LazyDiskSet("ws_injection"),
		rhm: dedup.LazyDefaultRHM("ws_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests each insertion point for injection vulnerabilities
// in parameters likely forwarded to WebSocket message processing.
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

	// Only test parameters with WS-related names.
	paramName := strings.ToLower(ip.Name())
	if !wsParamNames[paramName] {
		return nil, nil
	}

	// Dedup by insertion point.
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Baseline body from the original (unfuzzed) response, if captured. A pattern
	// already present here is static page content — e.g. a feature-flag list that
	// names DB engines ("userHasMySqlEnabled") or any page that literally contains
	// "49" — not an injection signal, so it is suppressed.
	var origBodyLower string
	if ctx.Response() != nil {
		origBodyLower = strings.ToLower(ctx.Response().BodyToString())
	}

	var results []*output.ResultEvent

	for _, test := range injectionTests {
		fuzzedRaw := ip.BuildRequest([]byte(test.payload))
		// BuildRequest produces well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, execErr := httpClient.Execute(fuzzedReq, http.Options{})
		if execErr != nil {
			if errors.Is(execErr, hosterrors.ErrUnresponsiveHost) {
				return nil, execErr
			}
			continue
		}

		// A WAF/CDN/auth/rate-limit page (IsBlockedResponse) or a 404/redirect
		// (not an error surface) is not the app echoing our payload — its body can
		// carry a token that trips one of these bare patterns (a catch-all/SPA 404
		// shell, a feature-flag JSON), so skip it before matching.
		if infra.IsBlockedResponse(resp) || !infra.IsErrorSurfaceStatus(resp) {
			resp.Close()
			continue
		}

		// Match against the body only, not the headers — a Server/CSP header
		// naming a DB engine must not trip a bare pattern.
		bodyLower := strings.ToLower(resp.Body().String())
		respContentType := ""
		if resp.Response() != nil {
			respContentType = resp.Response().Header.Get("Content-Type")
		}
		resp.Close()

		// XSS probes are pure markup-reflection oracles: the injected tag echoed
		// back only matters if it renders as HTML. A non-HTML response (a JSON API
		// echoing the payload in a validation error, text/plain, ...) treats the
		// tag as a data value that never executes — the FastAPI 422 JSON echo FP.
		// The SQLi / command / template categories match error text or evaluated
		// results, which legitimately appear in JSON, so gate the XSS category only.
		if test.category == "XSS" && modkit.IsNonHTMLReflectionContext(respContentType) {
			continue
		}

		// Template probes: require the literal payload to be gone (evaluated).
		if test.requireConsumed && strings.Contains(bodyLower, strings.ToLower(test.payload)) {
			continue
		}

		// For the SQLi / command / template categories the patterns are DB-error /
		// command-output / evaluated-result markers that must come from the SERVER,
		// not from our own echoed payload. Strip the reflected payload before
		// matching so its literal text cannot self-match — e.g. the UNION probe
		// "' UNION SELECT NULL--" echoed into a JSON error body contains the pattern
		// "union select". XSS keeps the raw body: there the pattern IS the payload
		// (already gated on HTML content-type above).
		matchBody := bodyLower
		if test.category != "XSS" {
			matchBody = strings.ReplaceAll(matchBody, strings.ToLower(test.payload), " ")
		}

		for _, pattern := range test.patterns {
			pl := strings.ToLower(pattern)
			// Must appear in the fuzzed response AND be absent from the baseline.
			if strings.Contains(matchBody, pl) && !strings.Contains(origBodyLower, pl) {
				results = append(results, &output.ResultEvent{
					URL:     urlx.String(),
					Matched: urlx.String(),
					ExtractedResults: []string{
						fmt.Sprintf("Category: WebSocket %s", test.category),
						fmt.Sprintf("Parameter: %s", ip.Name()),
						fmt.Sprintf("Payload: %s", test.payload),
						fmt.Sprintf("Matched pattern: %s", pattern),
					},
					MatcherStatus: true,
				})
				// One match per test is enough; move to next test.
				break
			}
		}
	}

	return results, nil
}
