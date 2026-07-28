package dashboardsig

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// confirmerFor returns the product's confirmer for the given path.
func confirmerFor(t *testing.T, productID, path string) *Confirmer {
	t.Helper()
	p := get(productID)
	require.NotNil(t, p, "product %q missing from the catalog", productID)
	for i := range p.Confirmers {
		if p.Confirmers[i].Path == path {
			return &p.Confirmers[i]
		}
	}
	t.Fatalf("product %q has no confirmer for %q", productID, path)
	return nil
}

func confirm(c *Confirmer, body string) (string, int, bool) {
	return c.Confirm(200, func(string) string { return "" }, body, strings.ToLower(body))
}

// TestConfirm_VLLMVersionRejectsGenericHealthEndpoint is the regression guard for
// the reported false positive: a marketing-tracking service was reported as an
// unauthenticated vLLM deployment at High severity because its /version response
// happens to contain the substring "version". /version returning JSON with a
// version key is a near-universal microservice convention, so the mere presence
// of that key cannot identify a product — vLLM's /version returns EXACTLY
// {"version":"<v>"} and nothing else, and it is that whole-body shape the
// confirmer now requires.
func TestConfirm_VLLMVersionRejectsGenericHealthEndpoint(t *testing.T) {
	t.Parallel()
	c := confirmerFor(t, "vllm", "/version")

	// The body that produced the false positive.
	tracking := `{"serviceName":"tracking","serviceVersion":{"version":"0.1","commit":"25e5afc2"},` +
		`"asrVersion":{"version":"8.317.0","commit":"0380e2dd"}}`
	_, _, ok := confirm(c, tracking)
	assert.False(t, ok, "a generic microservice /version payload must not confirm vLLM")

	for _, body := range []string{
		`{"version":"1.2.3","build":"abc123"}`,    // extra keys — not vLLM's shape
		`{"name":"svc","version":"1.2.3"}`,        // version is not the only key
		`{"status":"ok"}`,                         // no version at all
		`<html><body>version 1.2.3</body></html>`, // version-shaped text in a page
		`{"serviceVersion":{"version":"0.1"}}`,    // nested only
	} {
		_, _, ok := confirm(c, body)
		assert.Falsef(t, ok, "body %q must not confirm vLLM", body)
	}

	// A real vLLM /version response still confirms and still yields its version.
	version, _, ok := confirm(c, `{"version":"0.6.3.post1"}`)
	require.True(t, ok, "vLLM's own /version response must still confirm")
	assert.Equal(t, "0.6.3.post1", version)
}

// TestConfirm_VLLMPrimaryIsModelList pins the low-false-positive endpoint probed
// at normal intensity to the vLLM-unique model list rather than the ubiquitous
// /version path: vLLM stamps every entry with owned_by "vllm" and a
// max_model_len that upstream OpenAI does not emit.
func TestConfirm_VLLMPrimaryIsModelList(t *testing.T) {
	t.Parallel()
	p := get("vllm")
	require.NotNil(t, p)
	var primaryPaths []string
	for i := range p.Confirmers {
		if p.Confirmers[i].Primary {
			primaryPaths = append(primaryPaths, p.Confirmers[i].Path)
		}
	}
	// Asserted as a whole slice, so dropping the Primary flag entirely — which would
	// leave vLLM unprobed at normal intensity — fails just as loudly as marking the
	// wrong endpoint.
	require.Equal(t, []string{"/v1/models"}, primaryPaths,
		"the endpoint probed at normal intensity must be the vLLM-unique one")

	c := confirmerFor(t, "vllm", "/v1/models")
	vllm := `{"object":"list","data":[{"id":"meta-llama/Llama-3-8B","object":"model",` +
		`"owned_by":"vllm","root":"meta-llama/Llama-3-8B","max_model_len":8192}]}`
	_, signals, ok := confirm(c, vllm)
	require.True(t, ok, "a vLLM model list must confirm")
	assert.GreaterOrEqual(t, signals, 2, "list shape + vLLM ownership are two corroborating signals")

	// The upstream OpenAI API (and other compatible servers) must not be
	// misreported as vLLM — that is what the generic llm-openai-api entry covers.
	openai := `{"object":"list","data":[{"id":"gpt-4","object":"model","owned_by":"openai"}]}`
	_, _, ok = confirm(c, openai)
	assert.False(t, ok, "a non-vLLM OpenAI-compatible model list must not confirm vLLM")
}
