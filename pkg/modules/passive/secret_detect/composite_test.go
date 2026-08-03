package secret_detect

import "testing"

// zhipuSectionID is the verbatim value from the Netflix Pulse GraphQL false
// positive: a `"sectionId"` whose `<32-hex>.<16-letter>` shape matched Zhipu's
// `[A-F0-9]{32}\.[A-Z0-9]{16}` under the rule's case-insensitive flag.
const zhipuSectionID = "0c0adefef1cc44418f40de2d94159bc5.videoShopSection"

// discordPageToken is the verbatim value from the Netflix careers false positive:
// a base64url triple matching the Discord bot token layout whose first segment
// decodes to `3737b8c002ad400f0"` rather than a snowflake.
const discordPageToken = "MzczN2I4YzAwMmFkNDAwZjAi.HVDgtg.bqULZwukB2xJ3T1WXKLzyecEMhw"

func TestIsNamespacedResourceID(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"graphql section id", zhipuSectionID, true},
		{"uuid-ish id with camelCase type", "a64c38f0b0c64ac58ebc4d898dd99fa0.videoShopSection", true},
		{"longer camelCase resource type", "0c0adefef1cc44418f40de2d94159bc5.heroBannerSection", true},
		// Real composite secrets keep their finding: the trailing half is random.
		{"salesforce consumer key", salesforceConsumerKey, false},
		{"sendgrid style id.secret", "SG.aBcDeFgHiJkLmNoPqRsTuV.x7Yz90AbCdEfGhIjKlMnOpQrStUvWxYz1234", false},
		{"zoho style hex triple", "1000.6a3f2b1c8d9e4f5a6b7c8d9e0f1a2b3c.9f8e7d6c5b4a3928170615243342516f", false},
		{"jwt is not a namespaced id", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r3wa", false},
		// Shape guards.
		{"no dot", "0c0adefef1cc44418f40de2d94159bc5", false},
		{"trailing word too short", "0c0adefef1cc44418f40de2d94159bc5.vidShop", false},
		{"trailing word is all lowercase, no camelCase transition", "0c0adefef1cc44418f40de2d94159bc5.production", false},
		{"trailing word has consecutive uppercase", "0c0adefef1cc44418f40de2d94159bc5.videoSHOPsection", false},
		{"trailing segment carries a digit", "0c0adefef1cc44418f40de2d94159bc5.videoShopSection2", false},
		{"leading segment too short to be random", "abc.videoShopSection", false},
		{"leading segment has no digit", "abcdefghijklmnopqrst.videoShopSection", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNamespacedResourceID(tt.s); got != tt.want {
				t.Errorf("isNamespacedResourceID(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsCamelCaseWord(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"videoShopSection", true},
		{"heroBannerSection", true},
		{"aVeryLongIdentifier", true},
		{"short", false},            // below the length floor
		{"allloweralpha", false},    // no lower→upper transition
		{"ALLUPPERCASEWORD", false}, // consecutive uppercase
		{"videoSHOPsection", false}, // consecutive uppercase
		{"video1ShopSection", false},
		{"video_shop_section", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isCamelCaseWord(tt.s); got != tt.want {
				t.Errorf("isCamelCaseWord(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsMalformedDiscordBotToken(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"careers page token decodes to hex plus quote", discordPageToken, true},
		{"another careers page token", "MzMwZmRkMjhmZjc1M2EyOTIi.HUwehQ.pqiFZGE_E6r0s4HXTboDzZviObs", true},
		// A real bot token's first segment decodes to the bot's snowflake user id.
		{"real-format token decodes to a snowflake", pushProtectedFixture(t, "discord_snowflake_token"), false},
		{"undecodable first segment is left alone", "!!!!.HVDgtg.bqULZwukB2xJ3T1WXKLzyecEMhw", false},
		{"no dot separator is left alone", "MzczN2I4YzAwMmFkNDAwZjAi", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMalformedDiscordBotToken(tt.s); got != tt.want {
				t.Errorf("isMalformedDiscordBotToken(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

// TestValueShapeNoiseWiring pins that both new guards reach IsValueShapeNoise,
// including the Discord rule scoping.
func TestValueShapeNoiseWiring(t *testing.T) {
	if !IsValueShapeNoise("kingfisher.zhipu.1", "Zhipu (BigModel) API Key", zhipuSectionID) {
		t.Error("namespaced resource id not dropped by IsValueShapeNoise")
	}
	if !IsValueShapeNoise(discordBotTokenRuleID, "Discord Bot Token", discordPageToken) {
		t.Error("malformed discord token not dropped by IsValueShapeNoise")
	}
	// The Discord decode guard is scoped to its rule: another rule capturing the
	// same value keeps its finding.
	if IsValueShapeNoise("kingfisher.generic.1", "Generic Secret", discordPageToken) {
		t.Error("discord decode guard leaked outside its rule")
	}
}
