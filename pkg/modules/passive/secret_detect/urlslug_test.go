package secret_detect

import (
	"strings"
	"testing"
)

// nytPressMentionBody is the verbatim shape of the New York Times false positive:
// a press-mention hyperlink whose hostname supplies the rule's proximity keyword
// and whose article slug supplies the 32-character "API key".
const nytPressMentionBody = `<p>If you don't believe us, look we were in ` +
	`<a href="https://www.nytimes.com/2025/01/23/arts/what-to-do-nyc-arts-january-2025.html" target="_blank">The New York Times</a>. Past guests…</p>`

const nytSlug = "what-to-do-nyc-arts-january-2025"

func TestIsURLPathSlugMatchNYTPressMention(t *testing.T) {
	idx := strings.Index(nytPressMentionBody, nytSlug)
	if idx < 0 {
		t.Fatal("fixture does not contain the slug")
	}
	if !IsURLPathSlugMatch([]byte(nytPressMentionBody), nytSlug, idx, idx+len(nytSlug)) {
		t.Error("IsURLPathSlugMatch(nyt press-mention link) = false, want true")
	}
}

func TestIsURLPathSlugMatch(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		snippet string
		want    bool
	}{
		{
			name:    "article slug in link path",
			body:    `see <a href="https://www.nytimes.com/2025/01/23/arts/what-to-do-nyc-arts-january-2025.html">`,
			snippet: nytSlug,
			want:    true,
		},
		{
			name:    "slug as final path segment",
			body:    `fetch("https://cdn.example.com/press/great-big-story-about-things")`,
			snippet: "great-big-story-about-things",
			want:    true,
		},
		{
			name:    "escaped JSON-embedded link",
			body:    `{"html":"<a href=\"https://www.nytimes.com/2025/01/23/arts/what-to-do-nyc-arts-january-2025.html\">"}`,
			snippet: nytSlug,
			want:    true,
		},
		// --- shape guards: opaque tokens in a path are NOT slugs ---
		{
			name:    "slack webhook token in path",
			body:    pushProtectedFixture(t, "slack_webhook_url"),
			snippet: "XXXXXXXXXXXXXXXXXXXXXXXX",
			want:    false,
		},
		{
			name:    "uuid path segment is hex, not words",
			body:    `https://api.example.com/v1/550e8400-e29b-41d4-a716-446655440000`,
			snippet: "550e8400-e29b-41d4-a716-446655440000",
			want:    false,
		},
		{
			name:    "mixed alnum segment disqualifies",
			body:    `https://api.example.com/k/live-w4Kb7jRt-secret-aX9`,
			snippet: "live-w4Kb7jRt-secret-aX9",
			want:    false,
		},
		{
			name:    "underscore-bearing token is not a word slug",
			body:    `https://api.example.com/k/prod-key_material-here`,
			snippet: "prod-key_material-here",
			want:    false,
		},
		{
			name:    "single word has no hyphen",
			body:    `https://api.example.com/k/correcthorsebatterystaple`,
			snippet: "correcthorsebatterystaple",
			want:    false,
		},
		{
			name:    "one word plus digits is not enough words",
			body:    `https://api.example.com/k/release-2025`,
			snippet: "release-2025",
			want:    false,
		},
		// --- position guards: query/fragment and non-URL contexts ---
		{
			name:    "slug-shaped value in query string is not a link path",
			body:    `https://example.com/download?token=super-secret-token-value-here`,
			snippet: "super-secret-token-value-here",
			want:    false,
		},
		{
			name:    "value after fragment is not a link path",
			body:    `https://example.com/app#access-granted-token-material-here`,
			snippet: "access-granted-token-material-here",
			want:    false,
		},
		{
			name:    "assignment outside any URL",
			body:    `const apiKey = "what-to-do-nyc-arts-january-2025";`,
			snippet: nytSlug,
			want:    false,
		},
		{
			name:    "relative path has no scheme",
			body:    `<a href="/2025/01/23/arts/what-to-do-nyc-arts-january-2025.html">`,
			snippet: nytSlug,
			want:    false,
		},
		{
			name:    "not preceded by a path separator",
			body:    `https://example.com/prefix.what-to-do-nyc-arts-january-2025.html`,
			snippet: nytSlug,
			want:    false,
		},
		{
			name:    "partial segment: match continues into a longer token",
			body:    `https://example.com/what-to-do-nyc-arts-january-2025xyz`,
			snippet: nytSlug,
			want:    false,
		},
		{
			name:    "snippet absent from body",
			body:    `https://example.com/other`,
			snippet: nytSlug,
			want:    false,
		},
		{
			name:    "empty snippet",
			body:    `https://example.com/x`,
			snippet: "",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pass start=-1 so the guard resolves the span itself, exercising the
			// fallback path the batch caller uses.
			if got := IsURLPathSlugMatch([]byte(tt.body), tt.snippet, -1, -1); got != tt.want {
				t.Errorf("IsURLPathSlugMatch(%q) = %v, want %v", tt.snippet, got, tt.want)
			}
		})
	}
}

func TestIsWordSlug(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{nytSlug, true},
		{"press-release-2025", true},
		{"the-2025-annual-report", true},
		// Not slugs.
		{"", false},
		{"nohyphen", false},
		{"a-b", false},                 // no 3+ letter words
		{"what-to-do", false},          // only one 3+ letter word
		{"release-2025", false},        // only one word
		{"live-w4Kb-token", false},     // mixed alnum segment
		{"prod-key_material", false},   // '_' is not a slug byte
		{"trailing-hyphen-", false},    // empty segment
		{"-leading-hyphen", false},     // empty segment
		{"double--hyphen-word", false}, // empty segment
		{"550e8400-e29b-41d4", false},  // hex segments are mixed
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isWordSlug(tt.s); got != tt.want {
				t.Errorf("isWordSlug(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}
