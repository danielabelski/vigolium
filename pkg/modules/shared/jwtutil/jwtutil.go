// Package jwtutil provides shared JSON Web Token parsing and classification for
// the secret/JWT scanner modules. It centralises compact-JWT decoding and the
// recognition of low-value tokens — most importantly Cloudflare-Access-style
// pre-authentication "meta" tokens — so the modules don't each re-implement (and
// drift on) JWT handling.
package jwtutil

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
)

// IdentityClaims are payload claims whose presence (with a non-empty value)
// marks a JWT as carrying a real authenticated identity — i.e. a bearer
// credential.
var IdentityClaims = []string{
	"sub", "email", "preferred_username", "upn", "unique_name",
	"user_id", "userid", "uid", "username", "name", "oid",
}

// AuthorizationClaims are payload claims that grant scope / roles — another sign
// the token is a usable bearer credential rather than a metadata token.
var AuthorizationClaims = []string{
	"scope", "scp", "scopes", "roles", "role", "groups", "permissions", "entitlements",
}

// IsJWT reports whether s is structurally a compact JWT: three dot-separated
// segments whose first two are non-empty base64url. It does not require the
// segments to decode to JSON (use Decode for that).
func IsJWT(s string) bool {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts[:2] {
		if p == "" {
			return false
		}
		if _, err := decodeSegmentRaw(p); err != nil {
			return false
		}
	}
	return true
}

// Decode splits a compact JWT and base64url-decodes its header and payload
// segments into JSON objects. ok is false unless the snippet is a three-segment
// token whose first two segments are valid base64url-encoded JSON objects.
func Decode(token string) (header, payload map[string]any, ok bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, nil, false
	}
	if header, ok = decodeSegment(parts[0]); !ok {
		return nil, nil, false
	}
	if payload, ok = decodeSegment(parts[1]); !ok {
		return nil, nil, false
	}
	return header, payload, true
}

// IsPreAuthMetaToken reports whether a decoded JWT payload is a pre-authentication
// / metadata token: a Cloudflare-Access-style meta token (type=meta, or
// auth_status=NONE), or an edge bot-challenge token (see IsChallengeToken). These
// are framework-generated tokens the edge hands to an unauthenticated visitor —
// embedded in /cdn-cgi/access/login/...?meta=<jwt> URLs and reflected into the
// login page, or baked into a 403 interstitial — not the application's own JWTs,
// so they are not credentials and carry no meaningful claim-hygiene or
// weak-secret signal.
func IsPreAuthMetaToken(payload map[string]any) bool {
	if t, ok := payload["type"].(string); ok && strings.EqualFold(t, "meta") {
		return true
	}
	if status, ok := payload["auth_status"].(string); ok &&
		strings.EqualFold(strings.TrimSpace(status), "NONE") {
		return true
	}
	return IsChallengeToken(payload)
}

// IsChallengeToken reports whether a decoded JWT payload is an edge bot-protection
// proof-of-work challenge token rather than a credential.
//
// The shape is a `pow` (proof-of-work) claim paired with the puzzle parameters the
// client must solve — `ch`/`challenge` (the nonce) and `dif`/`difficulty` (the
// leading-zero-bit target). Netlify's bot-challenge interstitial serves exactly
// this on its 403 page:
//
//	{"iss":"netlify","sub":"<visitor IP>","aud":["sec-challenge.netlify.com"],
//	 "exp":…,"nbf":…,"iat":…,"ch":"2f91d310872a20e3","dif":16,"pow":true}
//
// It authorizes nothing: it is minted FOR the anonymous visitor, scoped to the
// challenge service, and expires in well under a minute. Without this guard the
// IP-valued `sub` reads as an identity claim and the token grades as a leaked
// High-severity credential on every challenged host.
//
// Both a `pow` claim and one puzzle parameter are required, so a real token that
// merely happens to carry a `ch`/`dif` claim is untouched — no bearer credential
// advertises a proof-of-work claim alongside its puzzle.
func IsChallengeToken(payload map[string]any) bool {
	if !nonEmptyClaim(payload["pow"]) {
		return false
	}
	for _, c := range []string{"ch", "challenge", "dif", "difficulty"} {
		if nonEmptyClaim(payload[c]) {
			return true
		}
	}
	return false
}

// IsPreAuthMetaTokenString decodes token and reports whether it is a pre-auth /
// metadata token (see IsPreAuthMetaToken). Returns false for anything that does
// not decode as a JWT.
func IsPreAuthMetaTokenString(token string) bool {
	_, payload, ok := Decode(token)
	if !ok {
		return false
	}
	return IsPreAuthMetaToken(payload)
}

// PayloadIsSensitive decides whether a decoded JWT payload represents a usable
// bearer credential (true) or a pre-auth / metadata token (false).
func PayloadIsSensitive(payload map[string]any) bool {
	// An explicit auth_status is the strongest signal, and it is decisive: "NONE" is
	// the Cloudflare Access pre-auth meta-token shape — unauthenticated, no usable
	// session — while any other non-empty status means the token represents an
	// authenticated session. Checked ahead of IsPreAuthMetaToken so an authenticated
	// status wins over a stray type=meta claim.
	if status, ok := payload["auth_status"].(string); ok && strings.TrimSpace(status) != "" {
		return !strings.EqualFold(strings.TrimSpace(status), "NONE")
	}

	// Everything else the edge mints for an anonymous visitor — a Cloudflare Access
	// type=meta token, a proof-of-work challenge — authorizes nothing. Delegating
	// keeps one list of pre-auth shapes rather than restating it here.
	if IsPreAuthMetaToken(payload) {
		return false
	}

	for _, c := range IdentityClaims {
		if nonEmptyClaim(payload[c]) && !isNetworkAddressClaim(payload[c]) {
			return true
		}
	}
	for _, c := range AuthorizationClaims {
		if nonEmptyClaim(payload[c]) {
			return true
		}
	}
	return false
}

// Classify reports whether snippet is structurally a JWT (decodable header +
// payload with an "alg" header) and, if so, whether its payload carries
// authenticated-credential material (see PayloadIsSensitive). Requiring an
// "alg" header avoids misclassifying an arbitrary dotted base64 triple that
// happens to decode to JSON as a JWT.
func Classify(snippet string) (isJWT, sensitive bool) {
	header, payload, ok := Decode(snippet)
	if !ok {
		return false, false
	}
	if _, hasAlg := header["alg"]; !hasAlg {
		return false, false
	}
	return true, PayloadIsSensitive(payload)
}

// IsLowValue reports whether snippet is a JWT we cannot confirm carries
// authenticated-credential material — either it does not decode as a JWT, or it
// decodes to a pre-auth / metadata token. Non-JWT snippets return false, so the
// downgrade this drives stays scoped to JWT findings.
func IsLowValue(snippet string) bool {
	isJWT, sensitive := Classify(snippet)
	return isJWT && !sensitive
}

// isNetworkAddressClaim reports whether an identity claim's value is a bare IP
// literal (v4 or v6) rather than a principal.
//
// An edge/CDN token routinely binds itself to the requester by putting the
// caller's own source address in `sub` — Netlify's bot-challenge token carries
// `"sub":"<visitor IP>"`. That is the address of whoever asked, not a user the
// token authenticates, so it must not read as an authenticated identity: any
// visitor's token names their own IP, and the token grants no access. Only bare
// address literals are excluded, so a genuine subject that merely contains digits
// and dots (a numeric user id, a dotted account path) still counts as identity.
func isNetworkAddressClaim(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

// nonEmptyClaim reports whether a decoded JSON claim value carries content.
// Empty strings, empty arrays/objects, and absent (nil) claims do not count.
func nonEmptyClaim(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(x) != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		// numbers, bools, etc. — present and non-null counts as content.
		return true
	}
}

// decodeSegmentRaw base64url-decodes a single JWT segment, tolerating both
// unpadded (raw) and padded encodings.
func decodeSegmentRaw(seg string) ([]byte, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return raw, nil
	}
	return base64.URLEncoding.DecodeString(seg)
}

// decodeSegment base64url-decodes a single JWT segment and parses it as a JSON
// object.
func decodeSegment(seg string) (map[string]any, bool) {
	if seg == "" {
		return nil, false
	}
	raw, err := decodeSegmentRaw(seg)
	if err != nil {
		return nil, false
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}
	return obj, true
}
