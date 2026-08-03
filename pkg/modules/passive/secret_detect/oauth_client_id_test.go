package secret_detect

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

// salesforceConsumerKey is the verbatim value from the Zendesk QA / klausapp
// false positive: a Connected App Consumer Key served as one entry in the public
// front-end `window.__CONFIG__` blob, beside the other integration identifiers.
const salesforceConsumerKey = "3MVG9fTLmJ60pJ5KxSmtobJLmmeX3Yr9sJrDKgSb2xhl1znSnx8kH1.e7BbBcInj7bhGxZij011PyyEMAP23X"

func TestIsSalesforceConsumerKey(t *testing.T) {
	tests := []struct {
		name    string
		snippet string
		want    bool
	}{
		{"connected app consumer key", salesforceConsumerKey, true},
		{"consumer key with surrounding space", "  " + salesforceConsumerKey + "  ", true},
		{"consumer secret is not prefixed", "1955279925992207737", false},
		{"unrelated secret", "AKIAIOSFODNN7EXAMPLE", false},
		{"google client id", "1234-abc.apps.googleusercontent.com", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSalesforceConsumerKey(tt.snippet); got != tt.want {
				t.Errorf("IsSalesforceConsumerKey = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPublicOAuthClientID(t *testing.T) {
	tests := []struct {
		name    string
		snippet string
		want    bool
	}{
		{"salesforce consumer key", salesforceConsumerKey, true},
		{"google oauth client id", "1234-abc.apps.googleusercontent.com", true},
		{"aws key is a real secret", "AKIAIOSFODNN7EXAMPLE", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPublicOAuthClientID(tt.snippet); got != tt.want {
				t.Errorf("IsPublicOAuthClientID = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPublicIdentifierRule(t *testing.T) {
	public := []string{
		"Stripe Publishable Key",
		"Mapbox Public Access Token",
		"Auth0 Client ID",
		"Facebook App ID",
		"Microsoft Entra Application Client ID",
		"Supabase Publishable Key",
		"Segment Public API Token",
		"Algolia Application ID",
		"Google Client ID",
		"Lob Publishable API Key",
		"MongoDB API PUBLIC Key",
		"eBay Sandbox Client ID",
	}
	for _, name := range public {
		t.Run("public/"+name, func(t *testing.T) {
			if !IsPublicIdentifierRule(name) {
				t.Errorf("IsPublicIdentifierRule(%q) = false, want true", name)
			}
		})
	}

	// The sensitive half of every pair, plus ordinary credential families, must
	// keep full severity.
	sensitive := []string{
		"Stripe API Key",
		"Google OAuth Client Secret",
		"AWS Access Key ID",
		"Slack Bot Token",
		"RSA Private Key",
		"Twilio Auth Token",
		"Discord Bot Token",
		"Zhipu (BigModel) API Key",
		// A hypothetical combined rule must not be downgraded on its public half.
		"Acme Client ID and Secret",
		"Acme Public/Private Key Pair",
	}
	for _, name := range sensitive {
		t.Run("sensitive/"+name, func(t *testing.T) {
			if IsPublicIdentifierRule(name) {
				t.Errorf("IsPublicIdentifierRule(%q) = true, want false", name)
			}
		})
	}
}

func TestPublicIdentifierRuleGradesInfo(t *testing.T) {
	for _, name := range []string{"Stripe Publishable Key", "Auth0 Client ID", "Mapbox Public Access Token"} {
		t.Run(name, func(t *testing.T) {
			sev, conf := SecretFindingSeverity(
				false, false, false, false, false, false, false, false, false, false,
				IsPublicIdentifier(name, "pk_live_51H8xExampleValue0000000000"),
			)
			if sev != severity.Info || conf != severity.Tentative {
				t.Errorf("got %v/%v, want Info/Tentative", sev, conf)
			}
		})
	}
	// A real credential family is untouched by the public-identifier floor.
	sev, _ := SecretFindingSeverity(
		false, false, false, false, false, false, false, false, false, false,
		IsPublicIdentifier("Stripe API Key", pushProtectedFixture(t, "stripe_secret_key")),
	)
	if sev != severity.High {
		t.Errorf("Stripe API Key graded %v, want High", sev)
	}
}

func TestPublicIdentifierDescription(t *testing.T) {
	desc := secretFindingDescription("Stripe Publishable Key", "pk_live_51H8xExampleValue0000000000", `pk_live_[0-9a-zA-Z]{24}`)
	if !strings.Contains(desc, "public half of a credential pair") {
		t.Errorf("description does not explain the public-identifier impact:\n%s", desc)
	}
	if strings.Contains(desc, "Leaked secret detected") {
		t.Errorf("description still uses the generic leaked-secret wording:\n%s", desc)
	}
}

// TestSalesforceConsumerKeyGradesInfo pins the end-to-end outcome: a named
// provider family baselines High, but the public-identifier floor overrides it.
func TestSalesforceConsumerKeyGradesInfo(t *testing.T) {
	sev, conf := SecretFindingSeverity(
		false, false, false, false, false, false, false, false, false, false,
		IsPublicOAuthClientID(salesforceConsumerKey),
	)
	if sev != severity.Info {
		t.Errorf("severity = %v, want Info", sev)
	}
	if conf != severity.Tentative {
		t.Errorf("confidence = %v, want Tentative", conf)
	}
}

func TestSalesforceConsumerKeyLabelAndDescription(t *testing.T) {
	if got := PatternLabel("Salesforce Connected App Consumer Key (Prefixed)", salesforceConsumerKey); got != "Salesforce consumer key (client ID)" {
		t.Errorf("PatternLabel = %q, want the Salesforce client-ID label", got)
	}
	desc := secretFindingDescription("Salesforce Connected App Consumer Key (Prefixed)", salesforceConsumerKey, `\b(3MVG9[A-Za-z0-9._~-]{20,180})\b`)
	if !strings.Contains(desc, "public half of an OAuth client") {
		t.Errorf("description does not explain the public-identifier impact:\n%s", desc)
	}
	if strings.Contains(desc, "Leaked secret detected") {
		t.Errorf("description still uses the generic leaked-secret wording:\n%s", desc)
	}
}
