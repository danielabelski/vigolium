package modkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestParseSetCookiePolicyUsesExactAttributes(t *testing.T) {
	p, ok := ParseSetCookiePolicy("secure_preference=httponly-value; Path=/prefs")
	require.True(t, ok)
	assert.Equal(t, "secure_preference", p.Name)
	assert.False(t, p.Secure, "attribute words in the cookie name/value are not flags")
	assert.False(t, p.HTTPOnly)

	p, ok = ParseSetCookiePolicy("session=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Partitioned")
	require.True(t, ok)
	assert.True(t, p.Secure)
	assert.True(t, p.HTTPOnly)
	assert.True(t, p.Partitioned)
	assert.Equal(t, "lax", p.SameSite)
	assert.NotEmpty(t, p.ValueFingerprint)
	assert.NotContains(t, p.ValueFingerprint, "abc")
}

func TestCookiePolicyRegistryResolvesCarriedSession(t *testing.T) {
	svc := httpmsg.NewServiceSecure("app.example", 443, true)
	set := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(svc, []byte("GET /login HTTP/1.1\r\nHost: app.example\r\n\r\n")),
		httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=abc; Secure; HttpOnly; SameSite=Strict\r\n\r\n")),
	)
	sc := &ScanContext{}
	sc.ObserveResponseCookies(set)

	carried := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(svc, []byte("POST /transfer HTTP/1.1\r\nHost: app.example\r\nCookie: sessionid=abc\r\n\r\n")), nil,
	)
	policies := sc.RequestCookiePolicies(carried)
	require.Len(t, policies, 1)
	assert.Equal(t, "strict", policies[0].SameSite)
	assert.True(t, LikelySessionCookie(policies[0].Name))
}

func TestLikelySessionCookieExcludesCSRFTokens(t *testing.T) {
	assert.True(t, LikelySessionCookie("connect.sid"))
	assert.True(t, LikelySessionCookie("access_token"))
	assert.False(t, LikelySessionCookie("XSRF-TOKEN"))
	assert.False(t, LikelySessionCookie("theme"))
}

func TestCookiePolicyRegistryHonorsDomainAndPathScope(t *testing.T) {
	r := &CookiePolicyRegistry{}
	r.Add("login.example.com", CookiePolicy{Name: "session", Path: "/", SameSite: "strict"})
	if _, ok := r.Resolve("app.example.com", "/", "session"); ok {
		t.Fatal("host-only cookie must not flow to a sibling subdomain")
	}

	r.Add("login.example.com", CookiePolicy{Name: "shared", Domain: "example.com", Path: "/", SameSite: "lax"})
	shared, ok := r.Resolve("app.example.com", "/account", "shared")
	require.True(t, ok)
	assert.Equal(t, "lax", shared.SameSite)

	r.Add("app.example.com", CookiePolicy{Name: "shared", Domain: "example.com", Path: "/account", SameSite: "none", Secure: true})
	specific, ok := r.Resolve("app.example.com", "/account/settings", "shared")
	require.True(t, ok)
	assert.Equal(t, "/account", specific.Path)
	assert.Equal(t, "none", specific.SameSite)

	root, ok := r.Resolve("app.example.com", "/public", "shared")
	require.True(t, ok)
	assert.Equal(t, "/", root.Path)
}

func TestDefaultCookiePath(t *testing.T) {
	assert.Equal(t, "/", defaultCookiePath("/login"))
	assert.Equal(t, "/account", defaultCookiePath("/account/login"))
	assert.Equal(t, "/", defaultCookiePath("/"))
}

func TestRequestCookiePoliciesBindsPolicyToOpaqueValue(t *testing.T) {
	svc := httpmsg.NewServiceSecure("app.example", 443, true)
	set := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(svc, []byte("GET /login HTTP/1.1\r\nHost: app.example\r\n\r\n")),
		httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: sessionid=first; Secure; SameSite=None; Path=/\r\n\r\n")),
	)
	sc := &ScanContext{}
	sc.ObserveResponseCookies(set)

	matching := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(svc, []byte("GET / HTTP/1.1\r\nHost: app.example\r\nCookie: sessionid=first\r\n\r\n")), nil,
	)
	require.Len(t, sc.RequestCookiePolicies(matching), 1)

	rotated := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(svc, []byte("GET / HTTP/1.1\r\nHost: app.example\r\nCookie: sessionid=second\r\n\r\n")), nil,
	)
	assert.Empty(t, sc.RequestCookiePolicies(rotated), "a policy from another cookie value must not upgrade evidence")
}

func TestObserveResponseCookiesRejectsBrowserInvalidPolicies(t *testing.T) {
	svc := httpmsg.NewServiceSecure("app.example.com", 443, true)
	rr := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(svc, []byte("GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")),
		httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n"+
			"Set-Cookie: wrongdomain=one; Domain=evil.example; Secure; SameSite=None\r\n"+
			"Set-Cookie: publicsuffix=two; Domain=com; Secure; SameSite=None\r\n"+
			"Set-Cookie: __Host-invalid=three; Domain=example.com; Path=/; Secure; SameSite=None\r\n\r\n")),
	)
	sc := &ScanContext{}
	sc.ObserveResponseCookies(rr)

	for _, name := range []string{"wrongdomain", "publicsuffix", "__Host-invalid"} {
		if _, ok := sc.cookiePolicies().Resolve("app.example.com", "/", name); ok {
			t.Fatalf("browser-rejected cookie %q must not enter the policy registry", name)
		}
	}
}
