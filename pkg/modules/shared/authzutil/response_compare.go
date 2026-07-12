package authzutil

import (
	"bytes"
	"encoding/json"
	"maps"
	"math"
	"slices"
	"strings"
)

// AuthzVerdict indicates whether authorization was enforced, bypassed, or uncertain.
type AuthzVerdict int

const (
	VerdictEnforced  AuthzVerdict = iota // Access was denied
	VerdictBypassed                      // Access was granted (potential vulnerability)
	VerdictUncertain                     // Could not determine
)

// String returns a human-readable label for an AuthzVerdict.
func (v AuthzVerdict) String() string {
	switch v {
	case VerdictEnforced:
		return "enforced"
	case VerdictBypassed:
		return "bypassed"
	default:
		return "uncertain"
	}
}

// ResponseSummary captures the key attributes of an HTTP response for comparison.
type ResponseSummary struct {
	StatusCode      int
	BodyLength      int
	ContentType     string
	Body            []byte
	HasErrorMessage bool
}

// ResponseComparison holds the result of comparing two HTTP responses.
type ResponseComparison struct {
	StatusCodeMatch       bool
	BodyLengthDelta       int
	BodyLengthRatio       float64
	ContentIdentical      bool
	StructurallyIdentical bool
	UserFieldsDiffer      bool
	DifferingFields       []string
	SharedFields          []string
}

// CompareOptions configures response comparison behavior.
type CompareOptions struct {
	SimilarityThreshold float64
	UserSpecificFields  []string
}

// DefaultCompareOptions returns sensible defaults for response comparison.
func DefaultCompareOptions() CompareOptions {
	return CompareOptions{
		SimilarityThreshold: 0.8,
		UserSpecificFields: []string{
			"username", "user_name", "email", "name", "display_name",
			"first_name", "last_name", "avatar", "profile_url",
		},
	}
}

// SummarizeResponse creates a ResponseSummary from raw response attributes.
func SummarizeResponse(statusCode int, contentType string, body []byte) *ResponseSummary {
	hasError := false
	if len(body) > 0 {
		hasError = ContainsEnforcementString(string(body))
	}
	return &ResponseSummary{
		StatusCode:      statusCode,
		BodyLength:      len(body),
		ContentType:     contentType,
		Body:            body,
		HasErrorMessage: hasError,
	}
}

// minStructuralShapeKeys is the smallest object-key count a shared JSON shape must
// have to assert structural identity on its own. Below it (e.g. a {status,error}
// wrapper) two unrelated responses could coincidentally share a shape, so the
// signal is not trusted.
const minStructuralShapeKeys = 3

// maxShapeBodyBytes caps the body size jsonShapeSignature will parse. Above it the
// parse+GC cost isn't worth the IDOR signal, so the shape check is skipped and the
// comparison falls back to the length ratio.
const maxShapeBodyBytes = 512 * 1024

// jsonShapeSignature returns a stable signature of a JSON body's structure (the
// sorted, deduplicated set of every object key at every depth) and the number of
// distinct keys. Two responses that are the same resource type share the
// signature even when their instance data (and body length) differ — exactly the
// IDOR signal a body-length ratio misses (a basket with 3 items vs one with 1 are
// the same shape). Returns ("", 0) for non-JSON/oversized bodies. Callers invoke
// this lazily (only when the cheaper length ratio is inconclusive), so it never
// runs on the common secured-endpoint path where probes are denied first.
func jsonShapeSignature(body []byte) (string, int) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || len(trimmed) > maxShapeBodyBytes || (trimmed[0] != '{' && trimmed[0] != '[') {
		return "", 0
	}
	var v any
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return "", 0
	}
	keys := map[string]struct{}{}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				keys[k] = struct{}{}
				walk(val)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return strings.Join(slices.Sorted(maps.Keys(keys)), ","), len(keys)
}

// CompareResponses compares a baseline response against a probe response.
func CompareResponses(baseline, probe *ResponseSummary, opts CompareOptions) *ResponseComparison {
	if baseline == nil || probe == nil {
		return &ResponseComparison{}
	}

	comp := &ResponseComparison{
		StatusCodeMatch:  baseline.StatusCode == probe.StatusCode,
		ContentIdentical: bytes.Equal(baseline.Body, probe.Body),
	}

	// Body length delta and ratio
	comp.BodyLengthDelta = probe.BodyLength - baseline.BodyLength
	if baseline.BodyLength > 0 {
		smaller := math.Min(float64(baseline.BodyLength), float64(probe.BodyLength))
		larger := math.Max(float64(baseline.BodyLength), float64(probe.BodyLength))
		comp.BodyLengthRatio = smaller / larger
	} else if probe.BodyLength == 0 {
		comp.BodyLengthRatio = 1.0
	}

	// Structural identity: same status and bodies close in length.
	comp.StructurallyIdentical = comp.StatusCodeMatch && comp.BodyLengthRatio >= opts.SimilarityThreshold

	// JSON shape fallback: when the length ratio was inconclusive (same status but
	// the bodies differ enough in size to fail the ratio), two instances of the
	// same resource type are still the same shape — e.g. Juice Shop
	// GET /rest/basket/6 (3 items) vs /rest/basket/5 (different items), a genuine
	// cross-user object read the length ratio would reject. Computed lazily here so
	// the parse is skipped on the common secured path (probes denied first) and on
	// close-length bodies. The content-differs, public-navigation, enforcement-
	// string, and determinism gates downstream still guard FPs.
	if comp.StatusCodeMatch && !comp.StructurallyIdentical {
		if baseShape, baseKeys := jsonShapeSignature(baseline.Body); baseKeys >= minStructuralShapeKeys {
			if probeShape, _ := jsonShapeSignature(probe.Body); baseShape == probeShape {
				comp.StructurallyIdentical = true
			}
		}
	}

	// Check for user-specific field differences in body text (simple substring check).
	// Full JSON field diffing is deferred to Layer 2.
	if !comp.ContentIdentical && len(opts.UserSpecificFields) > 0 {
		baselineStr := strings.ToLower(string(baseline.Body))
		probeStr := strings.ToLower(string(probe.Body))
		for _, field := range opts.UserSpecificFields {
			inBaseline := strings.Contains(baselineStr, field)
			inProbe := strings.Contains(probeStr, field)
			if inBaseline && inProbe {
				comp.SharedFields = append(comp.SharedFields, field)
			}
			if inBaseline != inProbe {
				comp.DifferingFields = append(comp.DifferingFields, field)
				comp.UserFieldsDiffer = true
			}
		}
	}

	return comp
}
