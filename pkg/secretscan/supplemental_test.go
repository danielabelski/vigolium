package secretscan

import "testing"

// TestSupplementalGenericCredential exercises the vigolium-authored, js-miner-derived
// "Generic Credential Assignment" rule: it should fire on a credential keyword
// embedded in an identifier and assigned a quoted value across a broad keyword set,
// while the entropy gate and quoted-value class keep it off low-entropy junk and
// bareword/markup captures.
func TestSupplementalGenericCredential(t *testing.T) {
	det, err := Default()
	if err != nil {
		t.Fatalf("build detector: %v", err)
	}

	const ruleID = "vigolium.generic.credential.1"

	// firesWith reports whether the supplemental rule captured exactly `want` on input.
	firesWith := func(input, want string) bool {
		for _, m := range det.Detect([]byte(input)) {
			if m.RuleID == ruleID && m.Secret == want {
				return true
			}
		}
		return false
	}
	hasRule := func(input string) bool {
		for _, m := range det.Detect([]byte(input)) {
			if m.RuleID == ruleID {
				return true
			}
		}
		return false
	}

	// Broad keyword set the kingfisher generics don't cover — all high enough entropy.
	hits := []struct{ in, secret string }{
		{`const apiToken = "aB3xZ9qL7mV4vR2n"`, "aB3xZ9qL7mV4vR2n"},
		{`client_id: 'a1B2c3D4e5F6g7H8'`, "a1B2c3D4e5F6g7H8"},
		{`bearer="eyAbc123Xyz789Qw"`, "eyAbc123Xyz789Qw"},
		{`session_key => "S3ss10nK3yV4lue99"`, "S3ss10nK3yV4lue99"},
		{"githubToken:`ghx_Ab12Cd34Ef56Gh78`", "ghx_Ab12Cd34Ef56Gh78"},
		{`myConsumerSecret := "cS3cr3tW7xQz2Lm"`, "cS3cr3tW7xQz2Lm"},
	}
	for _, h := range hits {
		if !firesWith(h.in, h.secret) {
			t.Errorf("expected %s to capture %q from %q", ruleID, h.secret, h.in)
		}
	}

	// Must NOT fire: low-entropy value, unquoted value, no credential keyword, or an
	// all-letter value (the MinDigits gate — a compiled-JS name-map like
	// `token:"acquireTokenSilent"` where the value carries no digit).
	misses := []string{
		`password = "aaaaaaaa"`,             // below the entropy floor
		`token: "true"`,                     // too short / low entropy
		`apiToken = unquotedValue99`,        // value is not quoted
		`greeting = "helloThereFriend"`,     // no credential keyword in the name
		`token:"acquireTokenSilent"`,        // all-letter code identifier — no digit
		`authorization:"authorizationRole"`, // webpack name map — no digit
	}
	for _, in := range misses {
		if hasRule(in) {
			t.Errorf("expected %s NOT to fire on %q", ruleID, in)
		}
	}

	// The JuiceShop password is captured by the tighter kingfisher.generic.5 (same
	// span, deduped) — assert it is still detected by *some* rule either way.
	if len(det.Detect([]byte(`testingPassword="IamUsedForTesting"`))) == 0 {
		t.Error("expected the JuiceShop testingPassword to be detected")
	}
}
