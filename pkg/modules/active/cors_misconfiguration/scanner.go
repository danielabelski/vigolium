package cors_misconfiguration

import (
	"fmt"
	"net"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
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
	// selective marks a probe whose signal is only meaningful when the server does
	// NOT reflect arbitrary origins: an origin derived from a trusted host by a
	// single structural mutation (a changed or removed '.') is reflected, but an
	// unrelated origin is not. runProbe enforces that negative control so a blanket
	// origin reflector (already reported by the Reflected Origin probe) is not
	// re-reported here.
	selective bool
	sev       severity.Severity
	desc      string
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
		sev:  severity.Low,
		desc: "The server sets Access-Control-Allow-Origin to wildcard (*) while also allowing credentials, which is a misconfiguration that browsers should reject but may indicate insecure CORS logic.",
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
		canaryOrigin: func(host, canary string) string { return "https://" + canary + "." + host },
		sev:          severity.Low,
		desc:         "The server trusts subdomains of the target host as allowed origins. An attacker controlling any subdomain (e.g. via subdomain takeover) can read cross-origin responses.",
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
		sev:  severity.Low,
		desc: "The server trusts origins on non-standard ports of the target host, which may be exploitable if other services run on those ports.",
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
	{
		// An origin identical to a trusted host except that its last '.' is replaced
		// by another character. A validator that exact-matches or correctly escapes
		// its allowlist rejects this; one that uses a regex with an unescaped '.'
		// (e.g. "https://.*example.com$") accepts it, because '.' matches any char.
		name: "Unescaped Dot in Origin Regex",
		originFunc: func(host string) string {
			m := replaceLastDot(host)
			if m == "" {
				return ""
			}
			return "https://" + m
		},
		check:     func(acao, _ string) bool { return acao != "" },
		selective: true,
		sev:       severity.Low,
		desc:      "The server's origin allowlist appears to use a regular expression with an unescaped '.' metacharacter. An origin identical to a trusted host except that a '.' is replaced by another character is still reflected in Access-Control-Allow-Origin, while an unrelated origin is not. An attacker can register a look-alike domain that satisfies the flawed pattern and read cross-origin responses on behalf of authenticated users.",
	},
	{
		// An origin formed by removing a '.' from a trusted host, so the trusted host
		// appears as a substring (sub.example.com -> subexample.com contains
		// "example.com"). A substring/contains/endsWith check accepts it; an exact
		// match does not. subexample.com is itself registrable, so it is directly
		// exploitable.
		name: "Origin Substring Match",
		originFunc: func(host string) string {
			m := deleteFirstDot(host)
			if m == "" {
				return ""
			}
			return "https://" + m
		},
		check:     func(acao, _ string) bool { return acao != "" },
		selective: true,
		sev:       severity.Low,
		desc:      "The server validates the Origin with a substring/suffix check rather than an exact match. An origin formed by removing a '.' from a trusted host (so the trusted host name appears as a substring) is still reflected in Access-Control-Allow-Origin, while an unrelated origin is not. An attacker can register a domain that embeds the trusted host name and read cross-origin responses on behalf of authenticated users.",
	},
}

// replaceLastDot returns host with its final '.' replaced by 'x'. It returns ""
// when the mutation is not meaningful — a host with no '.' or a bare IPv4 literal
// (where every label is numeric), so those hosts are skipped rather than probed
// with a nonsensical origin.
func replaceLastDot(host string) string {
	i := strings.LastIndexByte(host, '.')
	if i < 0 || isIPv4(host) {
		return ""
	}
	return host[:i] + "x" + host[i+1:]
}

// deleteFirstDot returns host with its first '.' removed, collapsing the first two
// labels into one so the remaining host name contains the trusted host as a
// substring. Same not-applicable rules as replaceLastDot.
func deleteFirstDot(host string) string {
	i := strings.IndexByte(host, '.')
	if i < 0 || isIPv4(host) {
		return ""
	}
	return host[:i] + host[i+1:]
}

// isIPv4 reports whether host is a dotted-decimal IPv4 literal. Dot mutations
// against an IP are meaningless, so callers skip them.
func isIPv4(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
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

	var results []*output.ResultEvent

	for _, probe := range probes {
		// Determine probe origin
		origin := probe.origin
		if probe.originFunc != nil {
			origin = probe.originFunc(host)
		}
		// A probe may opt out for this host (e.g. dot mutations against an IP or a
		// dotless host) by returning an empty origin.
		if origin == "" {
			continue
		}

		result, err := m.runProbe(ctx, httpClient, probe, origin)
		if err != nil {
			continue
		}
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// ScanPerHost retains direct-call compatibility for existing integrations and
// tests; registry dispatch uses ScanPerRequest via the declared scope.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	return m.ScanPerRequest(ctx, httpClient, scanCtx)
}

// corsHeaders sends a request carrying the given Origin and returns the response
// status and the two CORS headers. NoClustering bypasses the requester's
// short-lived response cache so confirmation replays actually re-hit the server.
func corsHeaders(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	origin string,
) (status int, acao, acac string, rawReq []byte, ok bool) {
	raw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), "Origin", origin)
	if err != nil {
		return 0, "", "", nil, false
	}
	// AddOrReplaceHeader produces well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return 0, "", "", raw, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", "", raw, false
	}
	return resp.Response().StatusCode,
		resp.Response().Header.Get("Access-Control-Allow-Origin"),
		resp.Response().Header.Get("Access-Control-Allow-Credentials"),
		raw,
		true
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
	probe corsProbe,
	origin string,
) (*output.ResultEvent, error) {
	status, acao, acac, modifiedRaw, ok := corsHeaders(ctx, httpClient, origin)
	if !ok {
		return nil, nil
	}

	// For subdomain bypass, the check function needs the actual sent origin
	passes := false
	if probe.originFunc != nil {
		// Subdomain bypass: ACAO must exactly match the sent evil origin
		passes = acao == origin
	} else {
		passes = probe.check(acao, acac)
	}

	if !passes {
		return nil, nil
	}

	// Status gate: a permissive ACAO on a non-2xx error/redirect response is not
	// a usable cross-origin read; drop it.
	if status < 200 || status >= 300 {
		return nil, nil
	}

	// Negative control for selective probes: a wholly-unrelated origin must NOT be
	// reflected. If it is, the server reflects arbitrary origins (reported by the
	// Reflected Origin probe), and this narrower structural signal would be a
	// duplicate false positive — drop it. Fail closed only on a completed reflection
	// of the control; an inconclusive fetch leaves the primary match standing.
	if probe.selective {
		control := "https://" + utils.RandomString(12) + ".com"
		if _, ca, _, _, cok := corsHeaders(ctx, httpClient, control); cok && ca == control {
			return nil, nil
		}
	}

	// Strict confirmation.
	if probe.canaryOrigin != nil {
		// Reflection-class: the server must echo a freshly-randomized origin that
		// still satisfies the probe's rule, proving it reflects an attacker-chosen
		// origin rather than matching a fixed allowlist. Fail OPEN on an
		// inconclusive fetch error (already matched once); drop only on a clean
		// non-reflection.
		host := ctx.Service().Host()
		confirmed, err := modkit.ConfirmReflection(2, func(canary string) (bool, error) {
			o := probe.canaryOrigin(host, canary)
			st, a, _, _, fok := corsHeaders(ctx, httpClient, o)
			if !fok {
				return false, fmt.Errorf("cors confirm fetch failed")
			}
			return st >= 200 && st < 300 && a == o, nil
		})
		if err == nil && !confirmed {
			return nil, nil
		}
	} else {
		// Fixed-value (null / wildcard+creds): re-issue the same origin and require
		// the signal to reproduce identically. Drop only on a clean, completed
		// re-check that no longer matches.
		if st2, a2, c2, _, ok2 := corsHeaders(ctx, httpClient, origin); ok2 {
			reproduces := st2 >= 200 && st2 < 300 && a2 == acao && c2 == acac
			if !reproduces {
				return nil, nil
			}
		}
	}

	target := ctx.Target()

	return &output.ResultEvent{
		URL:     target,
		Matched: target,
		Request: string(modifiedRaw),
		ExtractedResults: []string{
			fmt.Sprintf("ACAO: %s", acao),
			fmt.Sprintf("ACAC: %s", acac),
			fmt.Sprintf("Probe: %s", probe.name),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("CORS Misconfiguration: %s", probe.name),
			Description: probe.desc,
			Severity:    probe.sev,
			Confidence:  severity.Certain,
			Reference:   []string{"https://portswigger.net/web-security/cors"},
		},
	}, nil
}
