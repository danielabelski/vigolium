package secret_detect

import "strings"

// PatternLabel returns a short, human-readable classification of a detected
// secret — the "kind" of credential — for display alongside the matched value
// (it is rendered in the console line's leading bracket) so a reviewer can tell a
// JWT from a Google API key from a generic hex token at a glance.
//
// The Kingfisher rule name is the primary source of truth: it already names the
// pattern that fired ("Slack Token", "AWS Access Key ID", "RazorPay API Key", …),
// so it is returned verbatim for most matches. A handful of families are
// normalised to a shorter, consistent label because the rule name is generic or
// misleading and the module already classifies them for severity purposes: the
// AIza… key family (routinely mislabelled "Google Gemini API Key"), reCAPTCHA
// site keys, Google OAuth client IDs, and JWTs (which several rules match under
// assorted names). When the rule name is blank, a bare hex token is recognised
// structurally and "secret" is the last resort.
//
// The overrides are ordered most-specific first and mirror the severity ladder in
// SecretFindingSeverity, so the label always names the same family the severity
// downgrade keyed on.
func PatternLabel(ruleName, snippet string) string {
	switch {
	case IsReCaptchaSiteKey(ruleName):
		return "reCAPTCHA site key"
	case IsGoogleOAuthClientID(snippet):
		return "Google OAuth client ID"
	case IsGoogleAPIKey(ruleName, snippet):
		return "Google API key"
	}
	// A JWT is matched by several assorted rules; normalise them all to "JWT" so
	// the three-segment header.payload.signature token is recognisable at a glance.
	if isJWT, _ := ClassifyJWTSnippet(snippet); isJWT {
		return "JWT"
	}
	if name := strings.TrimSpace(ruleName); name != "" {
		return name
	}
	// Structural fallback for a nameless rule (Kingfisher effectively always names
	// its rules, so this is a defensive last resort).
	if isHexToken(snippet) {
		return "hex token"
	}
	return "secret"
}

// isHexToken reports whether s is a bare hexadecimal token of at least 32
// characters — an MD5/SHA digest or a generic hex-encoded secret. Used only as a
// fallback label when the rule name is blank.
func isHexToken(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) >= 32 && isHexRun(s)
}
