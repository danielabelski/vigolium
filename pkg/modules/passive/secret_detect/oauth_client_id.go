package secret_detect

import "strings"

// salesforceConsumerKeyPrefix is the fixed prefix every Salesforce Connected App
// Consumer Key (OAuth client_id) carries. The paired Consumer Secret has no such
// prefix, so the prefix alone separates the public identifier from the credential.
const salesforceConsumerKeyPrefix = "3MVG9"

// IsSalesforceConsumerKey reports whether the matched snippet is a Salesforce
// Connected App Consumer Key — the `3MVG9…` OAuth client_id.
//
// A Consumer Key is the PUBLIC half of a Connected App: it is placed in every
// /services/oauth2/authorize URL the browser is redirected to, so a SPA that
// starts a Salesforce login flow must ship it to the client. That is exactly how
// it surfaces here — as one entry in a front-end config blob alongside the other
// public integration identifiers (Intercom, Pendo, Slack, Gorgias):
//
//	window.__CONFIG__ = {…,"salesforceIdentifier":"3MVG9…","intercomIdentifier":…}
//
// Like a Google OAuth client ID, a match on the key alone is reported as
// informational rather than a leaked credential (see IsPublicIdentifierRule for
// the paired-secret rationale).
func IsSalesforceConsumerKey(snippet string) bool {
	return strings.HasPrefix(strings.TrimSpace(snippet), salesforceConsumerKeyPrefix)
}

// IsPublicOAuthClientID reports whether the matched snippet is the public half of
// an OAuth client, recognised from the value's own fixed shape — the Google OAuth
// client ID (`…apps.googleusercontent.com`) or the Salesforce Connected App
// Consumer Key (`3MVG9…`). Shape-based, so a rule that mis-attributes the family
// still lands on the right severity.
func IsPublicOAuthClientID(snippet string) bool {
	return IsGoogleOAuthClientID(snippet) || IsSalesforceConsumerKey(snippet)
}

// publicIdentifierNameMarkers are rule-name substrings that mark a family as the
// PUBLIC half of a credential pair rather than the credential: an OAuth client id,
// a publishable/public key, a widget app id, a site key. Matched case-insensitively
// against the rule name.
//
// Around 50 of the catalog's provider rules name such a family (Stripe Publishable
// Key, Mapbox Public Access Token, Auth0 / Facebook / LinkedIn / Microsoft Entra
// client and app ids, Supabase Publishable Key, Segment Public API Token, …). Every
// one of them is a NAMED provider family, so without this list each grades High —
// the same false positive the Google client ID and the Salesforce consumer key
// carve-outs already fix by hand, waiting to fire ~50 more ways.
var publicIdentifierNameMarkers = []string{
	"client id", "clientid",
	"publishable",
	"public key", "public access token", "public api token",
	"app id", "application id",
	"site key", "sitekey",
}

// credentialHalfNameMarkers are rule-name substrings that name the SENSITIVE half
// of a credential pair. A name carrying one of these is never treated as a public
// identifier, so a hypothetical "… Client ID and Secret" or "… Public/Private Key
// Pair" rule keeps full severity. No rule in the current catalog matches both
// lists — this is a guard against one being added.
var credentialHalfNameMarkers = []string{"secret", "private", "password"}

// IsPublicIdentifierRule reports whether a secret-scan rule NAME identifies a
// family that is public by design — see publicIdentifierNameMarkers.
//
// These values are meant to be shipped to the browser: an OAuth client id rides in
// every authorization redirect, a Stripe publishable key initialises Stripe.js, a
// Mapbox public token renders the map. Finding one in a response is expected, not a
// leak, so the finding is informational. The paired secret (client secret, secret
// key, private key) is a different value matched by a different rule, and keeps
// full severity.
//
// Name-based rather than value-based because these families have no shared value
// shape — the same approach IsReCaptchaSiteKey already takes.
func IsPublicIdentifierRule(ruleName string) bool {
	n := strings.ToLower(ruleName)
	for _, m := range credentialHalfNameMarkers {
		if strings.Contains(n, m) {
			return false
		}
	}
	for _, m := range publicIdentifierNameMarkers {
		if strings.Contains(n, m) {
			return true
		}
	}
	return false
}

// IsPublicIdentifier reports whether a match is a public-by-design identifier
// rather than a leaked credential, by value shape (IsPublicOAuthClientID) or by
// rule family (IsPublicIdentifierRule). It is the single gate behind
// SecretFindingSeverity's Info/Tentative floor, so every family recognised either
// way grades consistently.
func IsPublicIdentifier(ruleName, snippet string) bool {
	return IsPublicOAuthClientID(snippet) || IsPublicIdentifierRule(ruleName)
}

const publicIdentifierDescription = `**What it means:** This value is the public half of a credential pair — an OAuth client id, a publishable/public API key, or a widget application id. Values in this family are designed to be shipped to the browser: a client id rides in every authorization redirect, a publishable key initialises the vendor's client-side SDK, an app id identifies the widget to the vendor. Its presence in a response is expected, not a leaked credential. The sensitive half — the client secret, secret key, or private key — is a separate value matched by a separate rule, and is reported separately when present.

**How it's exploited:** Nothing on its own. A public identifier cannot authenticate or authorize a caller; it only identifies the application to the vendor. It becomes useful to an attacker when paired with a leaked secret, refresh token, or access token (each its own finding) — check this same response for those, as the two halves are often served together. Some families also carry a weak abuse ceiling worth confirming: a publishable key with an over-permissive vendor configuration, or a client id whose OAuth application allows a loose redirect_uri.

**Fix:** No action is required for the public identifier itself. Ensure the paired secret is never served in client-facing content; if one appears alongside this value, rotate it immediately.`

const salesforceConsumerKeyDescription = `**What it means:** This is a Salesforce Connected App Consumer Key (the 3MVG9… OAuth client_id) — the public half of an OAuth client. The Consumer Key is placed in the /services/oauth2/authorize URL the browser is redirected to, so any application that starts a Salesforce login flow from the front end must serve it to the client. Its presence in a response is expected, not a leaked credential. The sensitive half is the paired Consumer Secret, which is reported separately when present.

**How it's exploited:** Nothing on its own. A Consumer Key cannot authenticate or authorize a caller; it only identifies the Connected App. It becomes useful to an attacker only when paired with a leaked Consumer Secret, refresh token, or access token (each its own finding) — check this same response for those, as a leaked key often sits beside them. It is also worth confirming the Connected App's callback URLs are tightly restricted, since a permissive redirect_uri turns a public client_id into an authorization-code interception path.

**Fix:** No action is required for the Consumer Key itself. Ensure the paired Consumer Secret, refresh tokens, and access tokens are never served in client-facing content; if any of them appear alongside this key, rotate them immediately.`
