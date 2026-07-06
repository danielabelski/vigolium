package base64_data_detect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// base64Re matches interesting base64 encoded data prefixes:
//   - eyJ  = JSON ({"...)
//   - YTo  = PHP serialized array (a:...)
//   - Tzo  = PHP serialized object (O:...)
//   - PD8  = XML (<?...)
//   - PD9  = PHP (<?p...)
//   - aHR0cHM6L = https://
//   - aHR0cDo   = http:
//   - rO0  = Java serialized object
//
// The trailing class accepts the URL-safe alphabet (- and _) in addition to the
// standard one (+ /) and percent-encoding (%), so URL-safe blobs such as JWTs
// and OIDC state parameters are captured whole rather than cut at the first - or _.
var base64Re = regexp.MustCompile(`([^A-Za-z0-9+/]|^)(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[%a-zA-Z0-9+/_-]+={0,2}`)

var references = []string{
	"https://portswigger.net/kb/issues/00700200_base64-encoded-data-in-parameter",
	"https://cheatsheetseries.owasp.org/index.html",
}

// Module implements the Base64 Data Detection passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Base64 Data Detection module.
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
			modkit.PassiveScanScopeBoth,
		),
		rhm: dedup.LazyDefaultRHM("passive_base64_data_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest checks both request and response for interesting base64 encoded data.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent

	// Check response body. Skip WAF/CDN edge blocks: base64 on a challenge/error
	// page is the edge's, not the application's output.
	if ctx.Response() != nil && !modkit.IsEdgeBlockedResponse(ctx.Response()) {
		body := ctx.Response().BodyToString()
		if body != "" {
			ct := strings.ToLower(ctx.Response().Header("Content-Type"))
			if !isMediaContentType(ct) {
				if matches := findBase64Matches(body); len(matches) > 0 {
					if rhm == nil || rhm.ShouldCheck3(urlx, ctx.Request().Method(), ctx.Request().BodyToString(), "", "", "b64-resp") {
						decoded := decodeMatches(matches)
						extracted, preview := buildExtracted("response", decoded)
						results = append(results, &output.ResultEvent{
							ModuleID:         ModuleID,
							Host:             urlx.Host,
							URL:              urlx.String(),
							Matched:          urlx.String(),
							Request:          string(ctx.Request().Raw()),
							ExtractedResults: extracted,
							DedupKey:         structuralDedupKey(urlx.Host, "response", decoded),
							Info: output.Info{
								Name:        "Base64 Encoded Data in Response",
								Description: describeBase64("response", preview),
								Reference:   references,
								Tags:        []string{"base64", "encode", "interesting"},
							},
						})
					}
				}
			}
		}
	}

	// Check request (raw bytes include URL, headers, and body)
	if ctx.Request() != nil {
		raw := string(ctx.Request().Raw())
		if matches := findBase64Matches(raw); len(matches) > 0 {
			if rhm == nil || rhm.ShouldCheck3(urlx, ctx.Request().Method(), ctx.Request().BodyToString(), "", "", "b64-req") {
				decoded := decodeMatches(matches)
				extracted, preview := buildExtracted("request", decoded)
				results = append(results, &output.ResultEvent{
					ModuleID:         ModuleID,
					Host:             urlx.Host,
					URL:              urlx.String(),
					Matched:          urlx.String(),
					Request:          raw,
					ExtractedResults: extracted,
					DedupKey:         structuralDedupKey(urlx.Host, "request", decoded),
					Info: output.Info{
						Name:        "Base64 Encoded Data in Request",
						Description: describeBase64("request", preview),
						Reference:   references,
						Tags:        []string{"base64", "encode", "interesting"},
					},
				})
			}
		}
	}

	return results, nil
}

// findBase64Matches returns unique base64 matches from the input.
func findBase64Matches(s string) []string {
	allMatches := base64Re.FindAllString(s, 20)
	if len(allMatches) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(allMatches))
	var unique []string
	for _, match := range allMatches {
		// Trim the single leading boundary character the regex captured before
		// the prefix (anything that is not part of the base64/URL-safe alphabet).
		trimmed := strings.TrimLeft(match, " \t\r\n&?=;,\"'<>{}[]():/-_")
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		unique = append(unique, trimmed)
	}
	return unique
}

// decodedMatch pairs a raw base64 match with its decoded bytes so a single decode
// pass feeds both the human-readable extracted lines (buildExtracted) and the
// structural dedup key (structuralSignature). ok is false when the blob could not
// be decoded.
type decodedMatch struct {
	raw     string
	decoded string
	ok      bool
}

// decodeMatches decodes each base64 match exactly once, so callers that need both
// the decoded text and its structure don't decode the same blobs twice.
func decodeMatches(matches []string) []decodedMatch {
	out := make([]decodedMatch, len(matches))
	for i, m := range matches {
		dec, ok := decodeBase64Blob(m)
		out[i] = decodedMatch{raw: m, decoded: dec, ok: ok}
	}
	return out
}

// structuralDedupKey returns an explicit finding-identity key that groups base64
// findings by the JSON shape of their decoded blobs on a host, or "" to fall back
// to the default content hash. The motivating noise: SPA frameworks (e.g.
// Salesforce Lightning) embed a rotating token like {"nonce":"<changes-per-page>"}
// in every response, so a crawler produces one near-identical Info finding per URL,
// differing only by the token value. Keying on (host, source, JSON-shape) collapses
// those to a single finding while a blob with a different shape — a genuinely
// different encoded payload — keeps its own identity. Returns "" unless EVERY match
// decodes to a JSON object, so opaque/binary/non-JSON blobs (where a distinct value
// may itself be the signal) are never coalesced.
func structuralDedupKey(host, source string, matches []decodedMatch) string {
	sig, ok := structuralSignature(matches)
	if !ok {
		return ""
	}
	return "b64:" + host + ":" + source + ":" + sig
}

// structuralSignature builds a value-independent signature from a set of decoded
// base64 matches when every one is a JSON object, and reports ok=false otherwise.
// The signature is the sorted multiset of each object's sorted top-level key set,
// so two responses whose blobs share the same JSON shape collapse regardless of the
// (rotating) values, while a differing shape stays distinct.
func structuralSignature(matches []decodedMatch) (string, bool) {
	if len(matches) == 0 {
		return "", false
	}
	sigs := make([]string, 0, len(matches))
	for _, m := range matches {
		if !m.ok {
			return "", false
		}
		trimmed := strings.TrimSpace(m.decoded)
		if !strings.HasPrefix(trimmed, "{") {
			return "", false
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
			return "", false
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sigs = append(sigs, "{"+strings.Join(keys, ",")+"}")
	}
	sort.Strings(sigs)
	return strings.Join(sigs, ";"), true
}

// buildExtracted builds the ExtractedResults lines for a set of matches and
// returns the first decoded value as a short preview. Each match yields a raw
// line and, when the blob decodes to displayable text, an extra "(decoded)" line
// so the plaintext appears directly in the finding.
func buildExtracted(source string, matches []decodedMatch) (extracted []string, preview string) {
	extracted = make([]string, 0, len(matches)*2+1)
	extracted = append(extracted, "Source: "+source)
	for _, m := range matches {
		prefix := identifyPrefix(m.raw)
		extracted = append(extracted, fmt.Sprintf("%s: %s", prefix, modkit.Truncate(m.raw, 80)))
		decoded := displayableDecoded(m)
		if decoded == "" {
			continue
		}
		decodedLine := modkit.Truncate(decoded, 200)
		extracted = append(extracted, fmt.Sprintf("%s (decoded): %s", prefix, decodedLine))
		if preview == "" {
			preview = decodedLine
		}
	}
	return extracted, preview
}

// describeBase64 builds the per-finding description, appending a decoded preview
// when one is available.
func describeBase64(source, preview string) string {
	desc := fmt.Sprintf("Interesting base64-encoded information discovered within the %s. Manual review is recommended.", source)
	if preview != "" {
		desc += " Decoded preview: " + preview
	}
	return desc
}

// displayableDecoded renders an already-decoded base64 blob as a single-line,
// displayable string, or returns "" when it isn't decodable to text (e.g. binary
// Java serialized objects) so the finding only ever shows readable plaintext.
func displayableDecoded(m decodedMatch) string {
	if !m.ok {
		return ""
	}
	collapsed := collapseWhitespace(m.decoded)
	if !isDisplayableText(collapsed) {
		return ""
	}
	return collapsed
}

// decodeBase64Blob best-effort decodes a base64 string, tolerating the standard
// and URL-safe alphabets, percent-encoding, missing padding, and a tail the
// matcher may have cut mid-group.
func decodeBase64Blob(s string) (string, bool) {
	candidate := s
	if strings.Contains(candidate, "%") {
		if unescaped, err := url.QueryUnescape(candidate); err == nil {
			candidate = unescaped
		}
	}
	candidate = strings.TrimRight(candidate, "=")
	if candidate == "" {
		return "", false
	}
	// Drop up to three trailing characters to realign a tail cut mid-group,
	// trying both the standard and URL-safe alphabets on each attempt.
	for trim := 0; trim < 4 && len(candidate) > trim; trim++ {
		c := candidate[:len(candidate)-trim]
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			if decoded, err := enc.DecodeString(c); err == nil {
				return string(decoded), true
			}
		}
	}
	return "", false
}

// collapseWhitespace flattens runs of whitespace to single spaces for one-line display.
func collapseWhitespace(s string) string {
	if !strings.ContainsAny(s, " \t\n\r\f\v") {
		return s
	}
	return strings.Join(strings.Fields(s), " ")
}

// isDisplayableText reports whether s is valid UTF-8 text safe to show inline,
// rejecting binary blobs (e.g. Java serialized objects) and control-heavy data.
func isDisplayableText(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	var ctrl, total int
	for _, r := range s {
		total++
		if r == 0x00 {
			return false
		}
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			ctrl++
		}
	}
	return total > 0 && float64(ctrl)/float64(total) < 0.1
}

// identifyPrefix returns a human-readable label for the base64 prefix.
func identifyPrefix(s string) string {
	switch {
	case strings.HasPrefix(s, "eyJ"):
		return "JSON object"
	case strings.HasPrefix(s, "YTo"):
		return "PHP serialized array"
	case strings.HasPrefix(s, "Tzo"):
		return "PHP serialized object"
	case strings.HasPrefix(s, "PD8"):
		return "XML declaration"
	case strings.HasPrefix(s, "PD9"):
		return "PHP tag"
	case strings.HasPrefix(s, "aHR0cHM6L"):
		return "HTTPS URL"
	case strings.HasPrefix(s, "aHR0cDo"):
		return "HTTP URL"
	case strings.HasPrefix(s, "rO0"):
		return "Java serialized object"
	default:
		return "Base64 data"
	}
}

// isMediaContentType returns true for binary/media content types.
func isMediaContentType(ct string) bool {
	return strings.Contains(ct, "image/") ||
		strings.Contains(ct, "audio/") ||
		strings.Contains(ct, "video/") ||
		strings.Contains(ct, "octet-stream")
}
