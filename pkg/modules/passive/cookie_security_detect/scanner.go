package cookie_security_detect

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the Cookie Security Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Cookie Security Detect module.
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
		rhm: dedup.LazyDefaultRHM("passive_cookie_security_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes Set-Cookie headers for insecure attributes.
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
	if scanCtx != nil {
		scanCtx.ObserveResponseCookies(ctx)
	}

	// Collect Set-Cookie header values from response headers
	var setCookies []string
	for _, h := range ctx.Response().Headers() {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			setCookies = append(setCookies, h.Value)
		}
	}

	if len(setCookies) == 0 {
		return nil, nil
	}

	isHTTPS := strings.EqualFold(urlx.Scheme, "https")

	var results []*output.ResultEvent

	for _, cookie := range setCookies {
		policy, ok := modkit.ParseSetCookiePolicy(cookie)
		if !ok {
			continue
		}
		cookieName := policy.Name
		isSession := modkit.LikelySessionCookie(cookieName)

		var issues []string

		if isHTTPS && !policy.Secure {
			issues = append(issues, "Missing Secure flag")
		}

		if !policy.HTTPOnly {
			issues = append(issues, "Missing HttpOnly flag")
		}

		if policy.SameSite == "" {
			issues = append(issues, "Missing SameSite attribute")
		}

		// SameSite=None requires Secure: modern browsers reject a None cookie without
		// Secure, and it marks an intentionally cross-site cookie shipped insecurely.
		if policy.SameSite == "none" && !policy.Secure {
			issues = append(issues, "SameSite=None without Secure")
		}

		// Cookie name prefixes carry browser-enforced guarantees: __Secure- and
		// __Host- both require Secure, and __Host- forbids a Domain attribute.
		nameLower := strings.ToLower(cookieName)
		if strings.HasPrefix(nameLower, "__secure-") && !policy.Secure {
			issues = append(issues, "__Secure- prefix without Secure flag")
		}
		if strings.HasPrefix(nameLower, "__host-") {
			if !policy.Secure {
				issues = append(issues, "__Host- prefix without Secure flag")
			}
			if policy.Domain != "" {
				issues = append(issues, "__Host- prefix with a Domain attribute (violates the __Host- rule)")
			}
			if policy.Path != "/" {
				issues = append(issues, "__Host- prefix without Path=/ (violates the __Host- rule)")
			}
		}

		if len(issues) > 0 {
			kind := output.RecordKindObservation
			grade := output.EvidenceGradeObservation
			sev := severity.Info
			confidence := severity.Certain
			// Only likely authentication/session cookies rise to candidates, and
			// missing SameSite alone remains hygiene because modern browsers default
			// an unspecified SameSite value to Lax-like behavior.
			materialSessionIssue := isSession && (containsIssue(issues, "Missing Secure flag") || containsIssue(issues, "Missing HttpOnly flag"))
			if materialSessionIssue {
				kind = output.RecordKindCandidate
				grade = output.EvidenceGradeCandidate
				sev = severity.Low
				confidence = severity.Tentative
			}
			results = append(results, &output.ResultEvent{
				Host:          urlx.Host,
				URL:           urlx.String(),
				RecordKind:    kind,
				EvidenceGrade: grade,
				DedupKey:      fmt.Sprintf("cookie-policy|%s|%s|%s", urlx.Host, strings.ToLower(cookieName), strings.Join(issues, "|")),
				ExtractedResults: []string{
					fmt.Sprintf("Cookie: %s", cookieName),
					fmt.Sprintf("Issues: %s", strings.Join(issues, ", ")),
				},
				Info: output.Info{
					Description: fmt.Sprintf("Cookie %q: %s", cookieName, strings.Join(issues, ", ")),
					Severity:    sev,
					Confidence:  confidence,
				},
				Metadata: map[string]any{"cookie_class": map[bool]string{true: "session", false: "non-session"}[isSession]},
			})
		}
	}

	return results, nil
}

func containsIssue(issues []string, want string) bool {
	for _, issue := range issues {
		if issue == want {
			return true
		}
	}
	return false
}
