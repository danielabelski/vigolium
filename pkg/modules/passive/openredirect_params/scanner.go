package openredirect_params

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"go.uber.org/zap"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// bareHostRedirectRe matches a scheme-less hostname (optionally with a path/query),
// e.g. "evil.com", "www.evil.com/path" — a value that can still drive a redirect
// without an explicit scheme. It deliberately requires a dot + TLD so plain words
// like "Boulder" or "en-US" do not match.
var bareHostRedirectRe = regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)*\.[a-z]{2,}([:/?#].*)?$`)

// looksLikeRedirectTarget reports whether a parameter value is shaped like a URL,
// path, or host — i.e. something a redirect can actually point at. A redirect
// parameter *name* alone (redirect, url, callback, location, cb, …) is not enough:
// "location=Boulder" (a city filter), "cb=1782847109189" (a cache-buster), and
// "…getArticleUrlName…=1" (a name that merely contains "url") all carry a name
// that matches yet a value that can never be a redirect. Requiring the value to
// look like a target removes that entire noise class.
func looksLikeRedirectTarget(raw string) bool {
	if raw == "" {
		return false
	}
	// Best-effort decode, tolerating one layer of double-encoding, so encoded
	// forms like https%3A%2F%2Fevil.com and %252F… are judged on their decoded shape.
	dec := raw
	for i := 0; i < 2; i++ {
		u, err := url.QueryUnescape(dec)
		if err != nil || u == dec {
			break
		}
		dec = u
	}
	lower := strings.ToLower(strings.TrimSpace(dec))
	if lower == "" {
		return false
	}
	switch {
	case strings.Contains(lower, "://"): // http://evil.com, https://evil.com (any scheme)
		return true
	case strings.HasPrefix(lower, "//"): // //evil.com (protocol-relative)
		return true
	case strings.HasPrefix(lower, "/"): // /path or /\evil.com (internal / bypass target)
		return true
	case strings.HasPrefix(lower, `\`): // \evil.com, \/evil.com (backslash bypass)
		return true
	}
	// Fall back to the still-encoded form in case decoding did not apply.
	rlower := strings.ToLower(raw)
	if strings.HasPrefix(rlower, "%2f") || strings.HasPrefix(rlower, "%5c") || strings.Contains(rlower, "%3a%2f%2f") {
		return true
	}
	// Scheme-less bare host (evil.com, www.evil.com/path). No spaces are allowed,
	// which excludes multi-word values like "San Francisco".
	if !strings.ContainsAny(lower, " \t") && bareHostRedirectRe.MatchString(lower) {
		return true
	}
	return false
}

type Module struct {
	modkit.BasePassiveModule
	redirectRegex *regexp.Regexp
	rhm           dedup.Lazy[dedup.RequestHashManager]
}

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
			modkit.PassiveScanScopeRequest,
		),
		redirectRegex: regexp.MustCompile(`(?i)(?:redirect|callback|cb|url|uri|link|location)`),
		rhm:           dedup.LazyDefaultRHM("passive_openredirect_params"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes request parameters for potential open redirect vectors.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return results, nil
	}
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	urlx.Params.Iterate(func(key string, value []string) bool {
		if m.redirectRegex.MatchString(key) {
			joined := strings.Join(value, ",")
			// Skip empty / JS-placeholder values ("redirect=null", "url="): there is
			// no redirect target to abuse, so the bare parameter name is noise.
			if modkit.IsPlaceholderValue(joined) {
				return true
			}
			// The parameter name matching a redirect keyword is not enough — the
			// value must actually be shaped like a redirect target. This drops the
			// dominant false-positive class: city filters (location=Boulder),
			// cache-busters (cb=<timestamp>), and long identifiers whose name merely
			// contains "url" (…getArticleUrlName…=1).
			if !looksLikeRedirectTarget(joined) {
				return true
			}
			if rhm == nil || rhm.ShouldCheck3(urlx, ctx.Request().Method(), ctx.Request().BodyToString(), key, "", "inURL") {
				results = append(results, &output.ResultEvent{
					Host:             urlx.Host,
					URL:              urlx.String(),
					FuzzingParameter: key,
					Request:          string(ctx.Request().Raw()),
				})
			}
		}
		return true
	})

	// Annotate record with semantic tag if redirect params found
	if len(results) > 0 && scanCtx != nil && scanCtx.RemarksAnnotator != nil && scanCtx.RequestUUIDResolver != nil {
		uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(ctx.Request().ID())
		if uuid != "" {
			if err := scanCtx.RemarksAnnotator.AppendRemarks(context.Background(), map[string][]string{uuid: {"redirect-candidate"}}); err != nil {
				zap.L().Debug("openredirect_params: failed to annotate", zap.Error(err))
			}
		}
	}

	return results, nil
}
