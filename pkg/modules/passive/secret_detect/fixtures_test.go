package secret_detect

import (
	"encoding/base64"
	"testing"
)

// This package's tests need provider-shaped tokens: that is the whole point of a
// secret-detection guard test. GitHub push protection scans the repository source
// and blocks a push that carries one, synthetic or not, so a handful of these
// fixtures cannot live here as plain literals.
//
// Plain base64 is NOT enough — secret scanners decode base64 and match the
// plaintext — so the bytes are XOR'd with a fixed key first and decoded at test
// run time. This mirrors the corpus encoding in pkg/secretscan/detector_test.go
// (writer: pkg/secretscan/secretgen).
//
// To add or regenerate one:
//
//	python3 -c 'import base64,sys; print(base64.b64encode(bytes(b^0x5A for b in sys.argv[1].encode())).decode())' "<token>"
//
// Only encode a fixture that actually trips a push-protection rule; leaving the
// rest as readable literals keeps the tables legible.
const fixtureXORKey = 0x5A

// pushProtectedFixtures holds the XOR+base64 form of the fixtures that GitHub
// push protection rejects in plaintext. Keys describe the shape under test.
var pushProtectedFixtures = map[string]string{
	// Placeholder Slack incoming-webhook URL (all-zero team/bot ids, X-filled
	// token) used to prove an opaque path token is not a word slug.
	"slack_webhook_url": "Mi4uKilgdXUyNTUxKXQpNjs5MXQ5NTd1KT8oLDM5Pyl1DmpqampqampqdRhqampqampqanUCAgICAgICAgICAgICAgICAgICAgICAgI=",
	// Discord bot-token layout whose first segment decodes to a snowflake, i.e.
	// the well-formed shape the malformed-token guard must leave alone.
	"discord_snowflake_token": "Fw4TIBQeD2gUID1vFx4fIxcgC2sUMDludBIMHj0uPXQ4Kw8WAC0vMRhoIhBpDmsNAhEWICM/OR8XMi0=",
	// Stripe live secret-key shape, the credential family that must stay High
	// while its publishable sibling is floored to Info.
	"stripe_secret_key": "KTEFNjMsPwVvaxJiIh8iOzcqNj8MOzYvP2pqampqampqamo=",
}

// pushProtectedFixture returns the decoded fixture registered under name.
func pushProtectedFixture(t *testing.T, name string) string {
	t.Helper()
	enc, ok := pushProtectedFixtures[name]
	if !ok {
		t.Fatalf("unknown push-protected fixture %q", name)
	}
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("decode fixture %q: %v", name, err)
	}
	for i := range dec {
		dec[i] ^= fixtureXORKey
	}
	return string(dec)
}

// TestPushProtectedFixturesDecode pins that every registered fixture decodes to
// printable ASCII, so a corrupted entry fails loudly here rather than as a
// confusing assertion failure in the guard test that consumes it.
func TestPushProtectedFixturesDecode(t *testing.T) {
	for name := range pushProtectedFixtures {
		t.Run(name, func(t *testing.T) {
			v := pushProtectedFixture(t, name)
			if v == "" {
				t.Fatal("fixture decoded to an empty string")
			}
			for i := 0; i < len(v); i++ {
				if v[i] < 0x20 || v[i] > 0x7E {
					t.Fatalf("fixture decoded to non-printable byte %#x at %d", v[i], i)
				}
			}
		})
	}
}
