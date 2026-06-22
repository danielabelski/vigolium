package spring_actuator_misconfig

import (
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// lowSignalEndpoints are the actuator endpoints Spring Boot exposes publicly by
// default (the shipped `management.endpoints.web.exposure.include` is health,info)
// and that leak little on their own: /health reveals only an UP/DOWN status enum
// and /info only build/git metadata. Their exposure is reported at Low. The
// high-value endpoints (/env, /beans, /metrics, /loggers, /mappings) that dump
// credentials, live config and internal routes keep the module's High default.
var lowSignalEndpoints = map[string]bool{
	"health": true,
	"info":   true,
}

// endpointSeverity returns the per-finding severity for an actuator hit on the
// endpoint named name: Low for the publicly-exposed-by-default health/info
// endpoints, otherwise Undefined so the executor's assignModuleInfo falls back to
// the module's High default.
func endpointSeverity(name string) severity.Severity {
	if lowSignalEndpoints[name] {
		return severity.Low
	}
	return severity.Undefined
}

// testCase pairs a set of actuator paths to probe with a confirm predicate that
// must recognize the *structure* of that endpoint's actuator response — not a
// single generic word. A bare substring like "status", "scope" or "beans"
// appears in countless unrelated JSON payloads (e.g. Keycloak's
// /auth/resources/<realm>/<theme>/<anything> i18n message bundles, which are
// application/json and contain those words), so each confirm requires the
// telltale key:value pairing or co-occurring keys that only a real Spring Boot
// Actuator endpoint emits.
type testCase struct {
	// Name is the canonical actuator endpoint slug (e.g. "env"), used to build the
	// "actuator/<name>" suffix for reverse-proxy path-normalization bypass probing.
	Name     string
	Payloads []string
	confirm  func(body string) bool
}

func (c *testCase) Matches(content string) bool {
	return c.confirm != nil && c.confirm(content)
}

type Module struct {
	modkit.BaseActiveModule
	contentTypeRegex *regexp.Regexp
	ds               dedup.Lazy[dedup.DiskSet]
	testCases        []*testCase
}

// https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/springboot/springboot-env.yaml
func New() *Module {
	contentTypeRegex := regexp.MustCompile(`(?mi)(application/vnd\.spring-boot\.actuator\.v[0-9]\+json|application/json|application/vnd\.spring-boot.actuator)`)
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
		contentTypeRegex: contentTypeRegex,
		ds:               dedup.LazyDiskSet("spring_actuator_misconfig"),
		testCases:        initTestCases(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest scans the request for Spring Actuator misconfigurations.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// CandidateBasePaths yields the web root ("") plus each context-path prefix of
	// the observed URL, so an actuator at the root (/actuator/env) is probed
	// alongside one mounted under a context path (/api/actuator/env). The earlier
	// SplitPathRecursive walk skipped the root — the most common Spring Boot
	// layout — and was unbounded on deep URLs; CandidateBasePaths fixes both.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	host := urlx.Scheme + "|" + urlx.Host

	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	for _, path := range bases {
		for _, testCase := range m.testCases {
			blocked := false
			hit := false
			for _, payload := range testCase.Payloads {
				// Build the new path with payload (the actuator endpoint under this
				// directory) and probe it.
				newPath := path + "/" + payload

				rawReq, body, status, ok := m.fetchPathBody(ctx, httpClient, newPath)
				if !ok || !testCase.Matches(body) {
					// Remember a fronting-proxy block so we know the bypass is worth
					// trying for this endpoint below.
					if modkit.IsProxyBlockedStatus(status) {
						blocked = true
					}
					continue
				}

				// Soft-404 guard: reject when the matched actuator response is just
				// the host's wildcard shell (a server that 200s every path). Compares
				// against a cached host-wide random-path fingerprint; fails open on
				// probe error so a real actuator is never suppressed by a flaky probe.
				if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(body), "") {
					continue
				}

				// Sub-directory catch-all guard: probe a guaranteed-nonexistent sibling
				// under the SAME parent directory and drop the finding if it yields the
				// same actuator marker. This reproduces the /health-vs-/aaaa comparison
				// directly and catches catch-all static handlers (e.g. Keycloak's
				// /auth/resources/.../<path>) that the root-scoped wildcard probe above
				// cannot — the catch-all only fires under a specific path prefix.
				if m.siblingIsCatchAll(testCase, path, ctx, httpClient) {
					continue
				}

				hit = true
				results = append(results, &output.ResultEvent{
					URL:              urlx.Scheme + "://" + urlx.Host + newPath,
					Request:          rawReq,
					Response:         body,
					FuzzingParameter: path,
					// /health and /info are public-by-default and low-disclosure, so
					// they report Low; every other actuator endpoint leaves Severity
					// Undefined and inherits the module's High default.
					Info: output.Info{Severity: endpointSeverity(testCase.Name)},
				})
			}

			// Reverse-proxy path-normalization bypass: when a fronting proxy blocked
			// the actuator endpoint (401/403/405) but did not already serve it, try
			// the `..;/` family — multi-segment climbs scaled to the observed path
			// depth plus URL-encoded separator/slash variants (%3b, %23, %2f, %252f).
			// Once per host (web root present and first) so the extra requests only
			// land on a host that is actually proxy-protecting actuator.
			if path == "" && blocked && !hit && testCase.Name != "" {
				tc := testCase
				if res := modkit.ProbePathBypass(urlx.Path, "actuator/"+tc.Name, func(bypassPath string) *output.ResultEvent {
					rawReq, body, _, ok := m.fetchPathBody(ctx, httpClient, bypassPath)
					if !ok || !tc.Matches(body) {
						return nil
					}
					if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(body), "") {
						return nil
					}
					// Seed Name/Tags from the module so the bypass annotation
					// (appended by ProbePathBypass) yields a clean finding — this
					// module otherwise leaves Info empty for the runner to fill, and
					// assignModuleInfo only fills EMPTY fields.
					return &output.ResultEvent{
						URL:              urlx.Scheme + "://" + urlx.Host + bypassPath,
						Request:          rawReq,
						Response:         body,
						FuzzingParameter: bypassPath,
						Info: output.Info{
							Name:     m.Name(),
							Tags:     append([]string(nil), m.Tags()...),
							Severity: endpointSeverity(tc.Name),
						},
					}
				}); res != nil {
					results = append(results, res)
				}
			}
		}
	}

	return results, nil
}

// fetchPathBody issues a GET to newPath, carrying the original request's headers
// and service, and returns the raw request and response body only when the
// response is a 200 with an actuator-compatible content type. ok is false on any
// build/transport error or a non-matching status/content type.
func (m *Module) fetchPathBody(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	newPath string,
) (rawReq, body string, status int, ok bool) {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return "", "", 0, false
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, newPath)
	if err != nil {
		return "", "", 0, false
	}

	// SetPath produces well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return "", "", 0, false
	}
	defer resp.Close()

	if resp.Response() == nil {
		return "", "", 0, false
	}
	status = resp.Response().StatusCode
	if status != 200 {
		return "", "", status, false
	}
	if !m.contentTypeRegex.MatchString(resp.Response().Header.Get("Content-Type")) {
		return "", "", status, false
	}

	return string(modifiedRaw), resp.Body().String(), status, true
}

// siblingIsCatchAll probes a random, guaranteed-nonexistent sibling path under
// the same parent directory and reports whether it returns the SAME actuator
// marker match. A genuine actuator endpoint only emits its report at its own
// path; a catch-all handler (Keycloak i18n resources, SPA fallbacks, static file
// servers that 200 every child path) returns the same blob for the sibling too.
// Returns false on any probe/parse error so a flaky probe never suppresses a
// real finding.
func (m *Module) siblingIsCatchAll(
	tc *testCase,
	parentPath string,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) bool {
	siblingPath := parentPath + "/" + modkit.FreshCanary()
	_, body, _, ok := m.fetchPathBody(ctx, httpClient, siblingPath)
	if !ok {
		return false
	}
	return tc.Matches(body)
}

// containsAny reports whether body contains at least one of subs.
func containsAny(body string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(body, s) {
			return true
		}
	}
	return false
}

var (
	// healthStatusRe matches the actuator /health status field paired with one of
	// the Spring Boot Health status enum values (UP/DOWN/OUT_OF_SERVICE/UNKNOWN),
	// in compact or pretty-printed JSON. {"status":"UP"} is the minimal health
	// body, so the key:value pairing — not the bare word "status" — is the anchor.
	healthStatusRe = regexp.MustCompile(`"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"`)

	// metricNameRe matches a dotted Micrometer/JVM metric id as emitted in the
	// /metrics names array (jvm.memory.used, process.cpu.usage, system.cpu.count,
	// http.server.requests, tomcat.sessions.active, hikaricp.connections, ...).
	// These dotted ids are specific to the actuator metrics registry.
	metricNameRe = regexp.MustCompile(`"(jvm\.[a-z.]+|process\.[a-z.]+|system\.[a-z.]+|http\.server\.requests|tomcat\.[a-z.]+|logback\.events|hikaricp\.[a-z.]+|spring\.[a-z.]+)"`)
)

func initTestCases() []*testCase {
	return []*testCase{
		{
			// /env — Environment property dump. Always wrapped in the
			// propertySources/activeProfiles envelope; require it plus a corroborating
			// inner key so a config blob that merely mentions "server.port" is rejected.
			Name:     "env",
			Payloads: []string{"env", "actuator/env"},
			confirm: func(b string) bool {
				return strings.Contains(b, `"propertySources"`) &&
					containsAny(b,
						`"activeProfiles"`,
						`"name":"systemProperties"`,
						`"name":"systemEnvironment"`,
						`"local.server.port"`,
						`"server.ports"`,
					)
			},
		},
		{
			// /info — build & git metadata. Require the build or git block paired with
			// one of its inner fields so a bare "build"/"git" word doesn't match.
			Name:     "info",
			Payloads: []string{"info", "actuator/info"},
			confirm: func(b string) bool {
				return (strings.Contains(b, `"build"`) && containsAny(b, `"artifact"`, `"version"`, `"group"`)) ||
					(strings.Contains(b, `"git"`) && containsAny(b, `"commit"`, `"branch"`))
			},
		},
		{
			// /health — status enum. The {"status":"UP"} key:value pair is the anchor.
			Name:     "health",
			Payloads: []string{"health", "actuator/health"},
			confirm:  func(b string) bool { return healthStatusRe.MatchString(b) },
		},
		{
			// /metrics — names list or a single metric's measurements. Require a real
			// dotted Micrometer metric id, or the measurements/availableTags envelope
			// of a /metrics/{name} response.
			Name:     "metrics",
			Payloads: []string{"metrics", "actuator/metrics"},
			confirm: func(b string) bool {
				return metricNameRe.MatchString(b) ||
					(strings.Contains(b, `"measurements"`) && containsAny(b, `"availableTags"`, `"statistic"`, `"baseUnit"`))
			},
		},
		{
			// /loggers — configured/effective levels. configuredLevel/effectiveLevel
			// are essentially unique to the actuator loggers report; otherwise require
			// the levels-enum array alongside the loggers map.
			Name:     "loggers",
			Payloads: []string{"loggers", "actuator/loggers"},
			confirm: func(b string) bool {
				return containsAny(b, `"configuredLevel"`, `"effectiveLevel"`) ||
					(strings.Contains(b, `"levels"`) && strings.Contains(b, `"loggers"`))
			},
		},
		{
			// /beans — bean catalog. Each bean entry carries scope/type/dependencies/
			// aliases under a contexts→beans tree. Require that structural co-occurrence
			// so a page that merely contains the word "scope" (e.g. OAuth client scopes)
			// is not mistaken for a bean dump.
			Name:     "beans",
			Payloads: []string{"beans", "actuator/beans"},
			confirm: func(b string) bool {
				return strings.Contains(b, `"beans"`) &&
					containsAny(b, `"dependencies"`, `"aliases"`) &&
					containsAny(b, `"scope"`, `"contexts"`, `"type"`)
			},
		},
		{
			// /mappings — request mappings. dispatcherServlets / requestMappingConditions
			// / requestMappingHandlerMapping are unique to the actuator mappings report.
			Name:     "mappings",
			Payloads: []string{"mappings", "actuator/mappings"},
			confirm: func(b string) bool {
				return containsAny(b, `"dispatcherServlets"`, `"requestMappingConditions"`, `"requestMappingHandlerMapping"`) ||
					(strings.Contains(b, `"contexts"`) && strings.Contains(b, `"mappings"`))
			},
		},
	}
}
