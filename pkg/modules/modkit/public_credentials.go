package modkit

import "strings"

// This file holds value-shape predicates for credentials that are PUBLIC BY
// DESIGN — values a vendor's own flow requires the browser to carry, so finding
// one in a response is expected rather than a leak.
//
// They live in modkit because more than one module needs the same judgement and
// passive modules do not import each other: secret_detect uses them to floor a
// matched secret to Info, env_secret_exposure to suppress a public value that
// would otherwise read as a credential-shaped assignment. Encoding one vendor's
// format twice is how the two drift.

// SalesforceConsumerKeyPrefix is the fixed prefix every Salesforce Connected App
// Consumer Key (OAuth client_id) carries. The paired Consumer Secret has no such
// prefix, so the prefix alone separates the public identifier from the credential.
const SalesforceConsumerKeyPrefix = "3MVG9"

// HasSalesforceConsumerKeyPrefix reports whether s is a Salesforce Connected App
// Consumer Key — the `3MVG9…` OAuth client_id.
//
// A Consumer Key is the PUBLIC half of a Connected App: it is placed in every
// /services/oauth2/authorize URL the browser is redirected to, so a front end
// that starts a Salesforce login flow must ship it to the client. Surrounding
// whitespace is trimmed, since callers pass values sliced out of a page.
func HasSalesforceConsumerKeyPrefix(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), SalesforceConsumerKeyPrefix)
}

// IsReCaptchaSiteKeyShape reports whether s has the Google reCAPTCHA site-key
// shape: the literal prefix "6L" followed by 38 URL-safe-base64 characters
// (40 total). Both reCAPTCHA v2 and v3 site keys use this format.
//
// The site key is rendered into the widget on every protected page — it is the
// half the browser must have; the secret key is the server-side half.
//
// Written as a byte scan rather than a regexp because secret_detect calls it per
// surviving match while grading, and this keeps it allocation-free.
func IsReCaptchaSiteKeyShape(s string) bool {
	if len(s) != 40 || s[0] != '6' || s[1] != 'L' {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
