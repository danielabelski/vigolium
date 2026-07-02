package javascript_uri_sink

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var (
	// Matches javascript: URIs in href, src, action, formaction attributes.
	// Covers plain, mixed-case, URL-encoded, and HTML-entity-encoded variants.
	jsURIInAttrRe = regexp.MustCompile(
		`(?i)(?:href|src|action|formaction)\s*=\s*` +
			`(?:"(?:javascript|&#0*106;?|&#x0*6a;?)[^"]*"|` +
			`'(?:javascript|&#0*106;?|&#x0*6a;?)[^']*'|` +
			`(?:javascript|&#0*106;?|&#x0*6a;?)\S*)`,
	)

	// Matches URL-encoded javascript: prefix variants.
	jsURIEncodedRe = regexp.MustCompile(
		`(?i)(?:href|src|action|formaction)\s*=\s*["']?\s*` +
			`(?:%6a%61%76%61%73%63%72%69%70%74|` +
			`j%61v%61script|` +
			`java%09script|` +
			`java%0ascript|` +
			`java%0dscript)\s*:`,
	)
)

// Module implements the javascript: URI sink passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new JavaScript URI Sink Detection module.
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
		ds: dedup.LazyDiskSet("javascript_uri_sink"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess only accepts HTML responses.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// ScanPerRequest scans HTML responses for javascript: URI sinks.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	var results []*output.ResultEvent

	// Collect all matches from both patterns
	seen := make(map[string]bool)
	allMatches := jsURIInAttrRe.FindAllString(body, 20)
	allMatches = append(allMatches, jsURIEncodedRe.FindAllString(body, 20)...)

	// Extract request parameter values for reflection correlation
	paramValues := extractParamValues(ctx)

	for _, match := range allMatches {
		normalized := strings.TrimSpace(match)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true

		conf := severity.Tentative
		sev := severity.Info
		var reflectedParam string

		// Check if any request parameter value appears in the matched sink
		matchLower := strings.ToLower(match)
		for param, val := range paramValues {
			if len(val) >= 4 && strings.Contains(matchLower, strings.ToLower(val)) {
				conf = severity.Firm
				reflectedParam = param
				break
			}
		}

		// A javascript: URI is only an XSS *sink* when untrusted input reaches it.
		// With no reflected request parameter the URI is site-authored (or
		// framework-generated) code that runs the page's own script — an
		// observation, not a vulnerability — so it stays Info; only a reflected
		// parameter flowing into the URI escalates to Medium. Inert browser no-ops
		// (javascript:void(0)) and framework postback/form-submit helpers
		// (ASP.NET __doPostBack / WebForm_DoPostBackWithOptions, document.form.submit())
		// carry no URL-supplied script surface at all, so they are dropped
		// entirely: those were the systematic Medium false positives observed on
		// static ASP.NET WebForms pages (__doPostBack links, javascript:void(0)).
		if reflectedParam == "" && isInertJavaScriptURI(matchLower) {
			continue
		}
		if reflectedParam != "" {
			sev = severity.Medium
		}

		extracted := []string{
			fmt.Sprintf("Sink: %s", modkit.Truncate(normalized, 200)),
		}
		if reflectedParam != "" {
			extracted = append(extracted, fmt.Sprintf("Reflected parameter: %s", reflectedParam))
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "JavaScript URI Sink",
				Description: fmt.Sprintf("Found javascript: URI in HTML attribute: %s", modkit.Truncate(normalized, 120)),
				Severity:    sev,
				Confidence:  conf,
				Tags:        []string{"xss", "javascript-uri", "html-sink"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/79.html"},
			},
			Metadata: map[string]any{
				"cwe":             "CWE-79",
				"reflected_param": reflectedParam,
			},
		})
	}

	return results, nil
}

// inertJSURISubstrings are lowercased fragments that mark a javascript: URI as
// carrying no attacker-reachable script surface: browser no-ops that only cancel
// default link navigation, and framework-generated postback / form-submit
// helpers whose invoked symbol is static and framework-controlled. A match on
// any of these (in the absence of a reflected request parameter) is
// developer/framework boilerplate, not a sink.
var inertJSURISubstrings = []string{
	// Browser no-ops.
	"javascript:void(0)", "javascript:void 0", "javascript: void(0)",
	"javascript:;", "javascript:''", "javascript:\"\"",
	// ASP.NET WebForms postback helpers.
	"__dopostback", "webform_dopostback", "webform_postbackoptions",
	// Static form-submit navigation suppressor (document.<form>.submit()).
	".submit()",
}

// isInertJavaScriptURI reports whether a matched javascript: attribute is a
// browser-inert no-op or a framework-generated postback/submit helper that never
// executes URL-supplied input. matchLower must already be lowercased.
func isInertJavaScriptURI(matchLower string) bool {
	for _, inert := range inertJSURISubstrings {
		if strings.Contains(matchLower, inert) {
			return true
		}
	}
	return false
}

// extractParamValues collects parameter values from the request URL query and body.
func extractParamValues(ctx *httpmsg.HttpRequestResponse) map[string]string {
	params := make(map[string]string)

	urlx, err := ctx.URL()
	if err != nil {
		return params
	}

	if urlx.Params != nil {
		urlx.Params.Iterate(func(key string, values []string) bool {
			if len(values) > 0 {
				params[key] = values[0]
			}
			return true
		})
	}

	return params
}
