package sensitive_api_fields_detect

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// sensitiveFields are JSON field name patterns to detect.
// Each entry is checked as a quoted key in the response body.
var sensitiveFields = []struct {
	patterns []string // patterns to match (with quotes)
	label    string   // human-readable label
}{
	{
		patterns: []string{`"password":`, `"password" :`},
		label:    "password",
	},
	{
		patterns: []string{`"passwd":`, `"passwd" :`},
		label:    "passwd",
	},
	{
		patterns: []string{`"secret":`, `"secret" :`},
		label:    "secret",
	},
	{
		patterns: []string{`"api_key":`, `"api_key" :`, `"apiKey":`, `"apiKey" :`, `"api-key":`, `"api-key" :`},
		label:    "api_key/apiKey",
	},
	{
		patterns: []string{`"access_token":`, `"access_token" :`, `"accessToken":`, `"accessToken" :`},
		label:    "access_token/accessToken",
	},
	{
		patterns: []string{`"private_key":`, `"private_key" :`, `"privateKey":`, `"privateKey" :`},
		label:    "private_key/privateKey",
	},
	{
		patterns: []string{`"ssn":`, `"ssn" :`},
		label:    "ssn",
	},
	{
		patterns: []string{`"credit_card":`, `"credit_card" :`, `"creditCard":`, `"creditCard" :`, `"card_number":`, `"card_number" :`, `"cardNumber":`, `"cardNumber" :`},
		label:    "credit_card/cardNumber",
	},
}

// antiPatterns indicate the response is a schema or documentation page.
var antiPatterns = []string{
	`"$ref"`,
	`"swagger"`,
	`"openapi"`,
}

// exclusionSuffixes for "password" field to skip non-sensitive contexts
var passwordExclusions = []string{
	`"password_reset"`,
	`"password_policy"`,
}

// secretExclusions for "secret" field to skip non-sensitive contexts
var secretExclusions = []string{
	`"secret_question"`,
}

// Pre-lowercase the static match catalogs once at init so the per-response scan
// (which compares against the memoized lowercased body) doesn't re-lowercase
// these constants on every JSON response. Several patterns carry camelCase
// (apiKey, accessToken, …), so the lowercase form is required for matching.
func init() {
	for i := range sensitiveFields {
		for j := range sensitiveFields[i].patterns {
			sensitiveFields[i].patterns[j] = strings.ToLower(sensitiveFields[i].patterns[j])
		}
	}
	for i := range passwordExclusions {
		passwordExclusions[i] = strings.ToLower(passwordExclusions[i])
	}
	for i := range secretExclusions {
		secretExclusions[i] = strings.ToLower(secretExclusions[i])
	}
}

// Module implements the Sensitive API Fields Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Sensitive API Fields Detect module.
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
		ds: dedup.LazyDiskSet("sensitive_api_fields_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}
	// A WAF/CDN edge block's JSON error body is the edge talking, not the
	// application — a "password"/"secret" key in it is not an app field leak.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}

	// Only operate on JSON responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "application/json") {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host
	dedupKey := host + urlx.Path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if len(body) == 0 {
		return nil, nil
	}

	// Shared, memoized lowercased body (computed once per response across modules).
	bodyLower := ctx.Response().BodyLowerString()

	// Check anti-patterns: skip if this is a schema/doc response
	for _, ap := range antiPatterns {
		if strings.Contains(bodyLower, ap) {
			return nil, nil
		}
	}

	// Check for sensitive fields
	var found []string
	for _, sf := range sensitiveFields {
		matched := false
		for _, pat := range sf.patterns {
			// The key must be present AND carry a populated value. A field whose
			// only occurrences are null / true / false / "" is a redacted or
			// feature-flag field ({"password":null}, {"secret":false}) that leaks
			// nothing — matching the bare key name there is the systematic false
			// positive this gate removes.
			if fieldHasPopulatedValue(bodyLower, pat) { // pat pre-lowercased at init
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		// Apply exclusions for specific fields
		if sf.label == "password" {
			excluded := false
			for _, ex := range passwordExclusions {
				if strings.Contains(bodyLower, ex) { // ex pre-lowercased at init
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}
		if sf.label == "secret" {
			excluded := false
			for _, ex := range secretExclusions {
				if strings.Contains(bodyLower, ex) { // ex pre-lowercased at init
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		found = append(found, sf.label)
	}

	if len(found) == 0 {
		return nil, nil
	}

	desc := "JSON API response contains sensitive field names: " + strings.Join(found, ", ")

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: found,
			RecordKind:       output.RecordKindCandidate,
			EvidenceGrade:    output.EvidenceGradeCandidate,
			DedupKey:         "sensitive-api-fields|" + host + "|" + urlx.Path + "|" + ctx.Request().IdentityFingerprint(),
			Info: output.Info{
				Name:        "Sensitive API Fields Detected",
				Description: desc,
				// A passive NAME match (the value is never inspected for actual
				// sensitivity) is a review lead, not a confirmed leak — the module
				// text says "each hit needs review" — so it belongs at Low, not
				// Medium. The value gate below drops null/empty/boolean fields.
				Severity:   severity.Low,
				Confidence: severity.Tentative,
				Tags:       []string{"api", "sensitive-data", "information-disclosure", "pii"},
				Reference:  []string{"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"},
			},
			Metadata: map[string]any{
				"sensitiveFields": found,
			},
		},
	}, nil
}

// fieldHasPopulatedValue reports whether the given quoted-key pattern (e.g.
// `"password":`, pre-lowercased) appears in body followed by a populated value.
// A value is "populated" when it is a non-empty string, a number, or a nested
// object/array. It is NOT populated when it is the JSON literal null/true/false
// or an empty string "" — those are redacted or feature-flag fields that leak
// nothing, so matching the bare key there was the systematic false positive.
// Every occurrence is scanned; one populated value is enough.
func fieldHasPopulatedValue(body, keyPat string) bool {
	from := 0
	for {
		i := strings.Index(body[from:], keyPat)
		if i < 0 {
			return false
		}
		pos := from + i + len(keyPat)
		// Skip whitespace between the colon and the value.
		for pos < len(body) {
			c := body[pos]
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				pos++
				continue
			}
			break
		}
		from = pos // advance so the next iteration cannot re-match this key
		if pos >= len(body) {
			return false
		}
		rest := body[pos:]
		switch {
		case strings.HasPrefix(rest, `""`),
			strings.HasPrefix(rest, "null"),
			strings.HasPrefix(rest, "true"),
			strings.HasPrefix(rest, "false"):
			// Benign literal — keep scanning for another occurrence.
		case strings.HasPrefix(rest, `"`),
			strings.HasPrefix(rest, "{"),
			strings.HasPrefix(rest, "["):
			return true // non-empty string / object / array value
		case rest[0] == '-' || (rest[0] >= '0' && rest[0] <= '9'):
			return true // numeric value
		}
	}
}
