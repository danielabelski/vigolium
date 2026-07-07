package infra

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// uniformBlob returns n bytes cycling through all 256 values (entropy ≈ 8
// bits/byte), representing an opaque compressed/encrypted body.
func uniformBlob(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return string(b)
}

func TestLooksOpaqueBody(t *testing.T) {
	// A high-entropy blob past the minimum length is opaque.
	assert.True(t, LooksOpaqueBody(uniformBlob(2048)), "uniform-byte blob should read as opaque")

	// Natural markup — even a large, repetitive page — is not opaque.
	html := "<html><body>" + strings.Repeat("<div class=row>record: alice bob carol</div>\n", 200) + "</body></html>"
	assert.False(t, LooksOpaqueBody(html), "repetitive HTML should not read as opaque")

	// Short high-entropy bodies are below the min length → not flagged (too small to
	// judge, and a short XPath page is still worth probing).
	assert.False(t, LooksOpaqueBody(uniformBlob(64)), "short body must not be flagged opaque")

	// Empty body is never opaque.
	assert.False(t, LooksOpaqueBody(""))
}

func TestShannonEntropyBits(t *testing.T) {
	assert.InDelta(t, 8.0, ShannonEntropyBits(uniformBlob(256)), 0.001, "uniform 256-byte spread is 8 bits/byte")
	assert.Equal(t, 0.0, ShannonEntropyBits(""))
	assert.Equal(t, 0.0, ShannonEntropyBits(strings.Repeat("a", 100)), "single-symbol string has zero entropy")
}

func TestIsCDNInfraPath(t *testing.T) {
	assert.True(t, IsCDNInfraPath("/cdn-cgi/challenge-platform/h/b/fo/123"))
	assert.True(t, IsCDNInfraPath("/cdn-cgi/trace"))
	assert.True(t, IsCDNInfraPath("/CDN-CGI/rum")) // case-insensitive
	assert.True(t, IsCDNInfraPath("/cdn-cgi"))
	assert.False(t, IsCDNInfraPath("/"))
	assert.False(t, IsCDNInfraPath("/api/cdn-cgi-status")) // substring, not the reserved prefix
	assert.False(t, IsCDNInfraPath("/app/login"))
}
