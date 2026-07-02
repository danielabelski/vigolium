package secret_detect

import "testing"

func TestPatternLabel(t *testing.T) {
	// A structurally-valid JWT (header.payload.signature, header decodes to JSON
	// with alg/typ). Kept short but well-formed so ClassifyJWTSnippet recognises it.
	const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

	cases := []struct {
		name     string
		ruleName string
		snippet  string
		want     string
	}{
		{"recaptcha site key", "Google reCAPTCHA Key", "6LdZcXkpAAAAAJk7PVSqHC3DiV9F7U1ooUQdX1AZ", "reCAPTCHA site key"},
		{"google oauth client id", "Google OAuth Credentials", "1234567890-abcdefg.apps.googleusercontent.com", "Google OAuth client ID"},
		{"google api key by prefix", "Google Gemini API Key", "AIzaSyD-EXAMPLEEXAMPLEEXAMPLEEXAMPLE123", "Google API key"},
		{"google api key by rule name", "Google API Key", "someothervalue", "Google API key"},
		{"jwt normalised", "Some JWT-ish Rule", jwt, "JWT"},
		// A named vendor rule is surfaced verbatim — Kingfisher already classifies it.
		{"vendor rule surfaced verbatim", "RazorPay API Key", "rzp_test_2N5KOJaU7vGghW", "RazorPay API Key"},
		{"slack rule surfaced verbatim", "Slack Token", "xoxb-1111-2222-abcdef", "Slack Token"},
		// Blank rule name falls back to structural recognition, then "secret".
		{"hex fallback when rule blank", "", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "hex token"},
		{"secret last resort", "  ", "not-hex-and-no-rule!", "secret"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PatternLabel(tc.ruleName, tc.snippet); got != tc.want {
				t.Fatalf("PatternLabel(%q, %q) = %q, want %q", tc.ruleName, tc.snippet, got, tc.want)
			}
		})
	}
}

func TestIsHexToken(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"9f86d081884c7d659a2feaa0c55ad015", true},  // 32 lowercase hex (MD5)
		{"DEADBEEFDEADBEEFDEADBEEFDEADBEEF", true},  // uppercase hex, 32
		{"9f86d081", false},                         // too short
		{"9f86d081884c7d659a2feaa0c55ad01z", false}, // 'z' is not hex
		{"", false},
	}
	for _, tc := range cases {
		if got := isHexToken(tc.in); got != tc.want {
			t.Errorf("isHexToken(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
