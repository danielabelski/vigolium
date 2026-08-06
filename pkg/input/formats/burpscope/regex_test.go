package burpscope

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLiteralPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    string
		wantOK  bool
	}{
		{"anchored literal host", `^www\.example\.com$`, "www.example.com", true},
		{"unanchored literal", `example\.com`, "example.com", true},
		{"case-insensitive flag stripped", `(?i)^api\.example\.com$`, "api.example.com", true},
		{"escaped hyphen", `^my\-app\.example\.com$`, "my-app.example.com", true},
		{"port", `^8443$`, "8443", true},
		{"leading wildcard", `^.*\.example\.com$`, "", false},
		{"partial wildcard", `^v.*\.example\.com$`, "", false},
		{"alternation", `^(a|b)\.example\.com$`, "", false},
		{"character class", `^\d+\.example\.com$`, "", false},
		{"quantified escape", `^a\.*example\.com$`, "", false},
		{"trailing quantifier", `^example\.co?m$`, "", false},
		{"empty", "", "", false},
		{"anchors only", `^$`, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := literalPattern(tt.pattern)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLiteralPathPrefix(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
	}{
		{`^/.*`, "/"},
		{`^/api/.*`, "/api/"},
		{`^/api/v1$`, "/api/v1"},
		{"", "/"},
		{`^.*\.js$`, "/"},            // no fixed leading path
		{`^/abc*`, "/ab"},            // the quantified atom is not part of the prefix
		{`^/api/\d+/edit$`, "/api/"}, // stops at the character class
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			assert.Equal(t, tt.want, literalPathPrefix(tt.pattern))
		})
	}
}

func TestDisplayPattern(t *testing.T) {
	assert.Equal(t, "*.example.com", displayPattern(`^.*\.example\.com$`))
	assert.Equal(t, "v*.example.com", displayPattern(`^v.*\.example\.com$`))
	assert.Equal(t, "my-app.example.com", displayPattern(`^my\-app\.example\.com$`))
}

func TestTrimAnchors_EscapedDollarKept(t *testing.T) {
	// A trailing `\$` is a literal dollar sign in the path, not an end anchor.
	assert.Equal(t, `/price\$`, trimAnchors(`^/price\$`))
}
