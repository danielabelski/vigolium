package secret_detect

import (
	"encoding/base64"
	"strings"
)

// discordBotTokenRuleID is kingfisher.discord.2, whose pattern
// `([MNO][A-Z0-9_-]{23}\.[A-Z0-9_-]{6}\.[A-Z0-9_-]{27})` describes the Discord bot
// token layout structurally but anchors on nothing vendor-specific — so any
// base64url triple with those segment widths matches.
const discordBotTokenRuleID = "kingfisher.discord.2"

// discordSnowflakeMinDigits / discordSnowflakeMaxDigits bound a Discord snowflake
// id. Snowflakes are millisecond timestamps shifted left 22 bits, so ids minted
// since Discord's 2015 epoch are 17-18 digits and the range stays under 20 for the
// lifetime of the format.
const (
	discordSnowflakeMinDigits = 17
	discordSnowflakeMaxDigits = 20
)

// isMalformedDiscordBotToken reports whether a value matched by the Discord bot
// token rule cannot actually be one, because its first segment does not decode to
// a snowflake id.
//
// A real bot token is `base64url(<bot user snowflake>).<base64url timestamp>.<hmac>`
// — the leading segment decodes to the bot's user id as ASCII decimal digits, which
// is exactly why the rule can require a leading [MNO] (base64 of a leading ASCII
// digit '1'-'9'). The rule checks the encoding but never the decoding, so any
// 24-character base64url run starting M/N/O matches. Netflix's careers sites serve
// per-request page tokens in that shape:
//
//	MzczN2I4YzAwMmFkNDAwZjAi.HVDgtg.bqULZwukB2xJ3T1WXKLzyecEMhw
//
// whose first segment decodes to `3737b8c002ad400f0"` — a hex id plus the closing
// quote of the JSON string it was encoded from, not a snowflake.
//
// Decoding is the vendor's own documented structure, so this cannot suppress a real
// token: every genuine bot token decodes to digits by construction. A value that
// does not decode at all is left alone (ok=false → not malformed), keeping the
// module's "can't tell → keep the finding" conservatism.
func isMalformedDiscordBotToken(s string) bool {
	first, _, found := strings.Cut(s, ".")
	if !found {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		// Not decodable as base64url — no structural claim to make either way.
		return false
	}
	if len(raw) < discordSnowflakeMinDigits || len(raw) > discordSnowflakeMaxDigits {
		return true
	}
	for i := 0; i < len(raw); i++ {
		if !isDigitByte(raw[i]) {
			return true
		}
	}
	return false
}

// namespacedIDMinWordLen is the shortest trailing camelCase word treated as a
// resource-type name. Short suffixes (`.prod`, `.v2Beta`) stay out of scope so the
// guard only fires on an unmistakable identifier.
const namespacedIDMinWordLen = 8

// namespacedIDMinRandomLen is the shortest leading segment treated as the random
// half of the composite — long enough that the value really is `<random>.<word>`
// rather than two ordinary words separated by a dot.
const namespacedIDMinRandomLen = 16

// isNamespacedResourceID reports whether s is a `<random>.<camelCaseWord>`
// namespaced resource id rather than a two-part `id.secret` credential.
//
// Several providers format a key as `<public id>.<secret>` — Zhipu's is
// `[A-F0-9]{32}.[A-Z0-9]{16}` — and the catalog scores entropy over the WHOLE
// value. Concatenating the two halves lifts the composite over the threshold even
// when neither half would reach it alone: Zhipu's rule demands 4.0 bits/byte, and
// while the hex half scores only 3.519 and `videoShopSection` 3.328, together they
// score 4.189. A GraphQL section id lands exactly there:
//
//	"sectionId":"0c0adefef1cc44418f40de2d94159bc5.videoShopSection"
//
// where `videoShopSection` is 16 letters and matches `[A-Z0-9]{16}` under the
// rule's case-insensitive flag — graded a High Zhipu API key. Re-scoring each
// segment against the rule's own threshold is not the fix: a 32-char hex string can
// never reach 4.0 bits/byte, so that would drop every genuine Zhipu key too.
//
// Both halves must fit for the guard to fire: a trailing camelCase word (see
// isCamelCaseWord) and a leading random-looking run of namespacedIDMinRandomLen+
// alphanumerics containing a digit. That keeps it off real composite secrets, whose
// trailing half is a random token — a JWT's base64 payload, SendGrid's
// `SG.<id>.<secret>`, Zoho's `1000.<hex>.<hex>`, and the Salesforce consumer key
// all carry digits in the final segment and so fail isCamelCaseWord outright.
//
// Rule-agnostic, so it covers all ~90 dot-composite rules in the catalog, not just
// Zhipu's.
func isNamespacedResourceID(s string) bool {
	i := strings.LastIndexByte(s, '.')
	if i < 0 || !isCamelCaseWord(s[i+1:]) {
		return false
	}
	// Some earlier segment must be the random half. Walk the '.'-delimited segments
	// in place — this runs on every untrusted match, so it must not allocate.
	start := 0
	for j := 0; j <= i; j++ {
		if j < i && s[j] != '.' {
			continue
		}
		seg := s[start:j]
		start = j + 1
		if len(seg) < namespacedIDMinRandomLen {
			continue
		}
		if _, hasDigit, hasOther := segClass(seg); hasDigit && !hasOther {
			return true
		}
	}
	return false
}

// isCamelCaseWord reports whether seg is a camelCase code identifier — all ASCII
// letters, at least namespacedIDMinWordLen long, with at least one lower→upper
// transition and no two consecutive uppercase letters.
//
// The transition requirement is what separates a spelled-out resource type
// (`videoShopSection`) from a random token: a random alphanumeric of this length
// almost always carries a digit (failing the all-letters test outright) and, when
// it does not, its capitals clump into consecutive runs that a camelCase identifier
// never has. Rejecting consecutive uppercase also keeps acronym-style constants and
// base64 runs (`XKLZYECEMHW`) out.
func isCamelCaseWord(seg string) bool {
	if len(seg) < namespacedIDMinWordLen || !isLetterByte(seg[0]) {
		return false
	}
	sawTransition := false
	for i := 1; i < len(seg); i++ {
		c := seg[i]
		if !isLetterByte(c) {
			return false
		}
		if !isUpperByte(c) {
			continue
		}
		// Two capitals in a row is an acronym or a base64 run, not camelCase.
		if isUpperByte(seg[i-1]) {
			return false
		}
		sawTransition = true
	}
	return sawTransition
}
