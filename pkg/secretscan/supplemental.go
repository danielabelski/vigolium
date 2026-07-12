package secretscan

import "github.com/vigolium/vigolium/pkg/secretscan/catalog"

// supplementalRules returns vigolium-authored rules appended to the generated
// kingfisher catalog at load time (see LoadCatalog). They cover generic credential
// shapes the kingfisher provider rules miss — a credential KEYWORD embedded in a
// variable/property name, assigned a QUOTED value — which is the dominant way weak
// or test credentials leak into compiled JS bundles (e.g. OWASP Juice Shop ships
// `testingPassword="IamUsedForTesting"` in main.js).
//
// The regex shape is derived from the js-miner Burp extension's SECRETS_REGEX
// (Apache-2.0, github.com/PortSwigger/js-miner): a broad keyword alternation, an
// assignment operator, and a quoted value whose character class already excludes
// markup/code punctuation. Unlike the kingfisher generics this anchors on a wider
// keyword set (token, bearer, authorization, client id, session/consumer/public/auth
// keys, ssh/github/slack tokens, aws keys) and accepts shorter quoted values, so it
// extends recall without touching the provider rules. (js-miner's second pattern,
// HTTP_BASIC_AUTH_SECRETS, is deliberately NOT ported — kingfisher.auth.1 "HTTP
// Basic Authorization Header" already covers `Basic <base64>`, better-anchored and
// at medium confidence.)
//
// The rule is Src "vigolium" + low confidence on purpose: that keeps it OUT of the
// trusted tier (finding.go GradeMatch trusts only high-confidence kingfisher rules),
// so its captures pass through the module's value-shape FP guards and land at the
// low-signal Suspect severity, folded into the per-host "Low-confidence
// secret-shaped matches" bundle rather than shown as standalone High findings. The
// vigolium.generic.* id prefix is what routes it there
// (secret_detect.IsGenericSecretRule), and the "Generic Credential Assignment" name
// is what subjects its captures to the generic-family identifier-slug guards
// (secret_detect.isGenericCredentialRule).
func supplementalRules() []catalog.Rule {
	// A single, double, or back quote — written with \x escapes so the Go string and
	// the RE2 class both stay readable (\x22 = ", \x27 = ', \x60 = `).
	const q = `[\x22\x27\x60]`

	return []catalog.Rule{
		{
			ID:   "vigolium.generic.credential.1",
			Name: "Generic Credential Assignment",
			Src:  "vigolium",
			// [prefix] KEYWORD [suffix] [quote]? assignment quote VALUE quote.
			// The keyword may sit anywhere inside the identifier (`testingPassword`,
			// `myApiKey`), the assignment is any run of :/= (`=`, `:`, `:=`, `=>`), and
			// the value is required to be quoted — the quoting plus the js-miner value
			// class (no whitespace/markup/braces) is what keeps this off page markup.
			// The value is the SOLE capturing group (positional, not named) so entropy
			// AND MinDigits are enforced on the value span, not the whole match — see
			// resolveCapture's reqUseFull. The keyword alternation is minimal: because
			// the `[\w$]{0,40}`/`{0,20}` fillers let a keyword sit anywhere in the
			// identifier, any compound keyword that merely CONTAINS a shorter branch as a
			// substring already matches via that shorter branch — so e.g.
			// `aws_secret_access_key`/`slack_bot_token` need no branch of their own (the
			// bare `secret`/`token` cover them), and the `X[_-]key` group's suffix reduces
			// to `key|id` (a `_token`/`_secret` suffix is covered by bare `token`/`secret`).
			Re: `(?i)[\w$]{0,40}` +
				`(?:id_dsa|authorization|password|passwd|irc[_-]?pass|bearer|secret|token|` +
				`(?:api|access|auth|session|consumer|public|ssh|encrypt|decrypt|github|client)[_-]?(?:key|id))` +
				`[\w$]{0,20}` + q + `?\s*[:=]{1,2}>?\s*` + q +
				`([\w\-/~!@#$%^&*+]{5,120})` + q,
			// Prefilter literals covering every alternation branch (each branch contains
			// one of these as a substring once lowercased).
			Kw:      []string{"pass", "secret", "token", "bearer", "authorization", "key", "client", "github", "id_dsa"},
			Entropy: 3.3, // same bar as the kingfisher generic family (generic.3/.4/.5)
			// Require a digit in the VALUE. Corpus-tuned (483 roche DBs): the dominant
			// FP of this broad rule is compiled-JS name maps — a credential keyword in a
			// minified function/property name mapped to another all-letter identifier
			// (`token:"acquireTokenSilent"`, `authorization:"authorizationGroups"`) and
			// module/URL paths (`"Magento_Customer/js/change-email-password"`). Real
			// keys/tokens carry digits; an all-letter password value is still covered by
			// kingfisher.generic.5, so this loses no genuine leak the scanner had.
			MinDigits:  1,
			Confidence: "low",
			Visible:    true,
		},
	}
}
