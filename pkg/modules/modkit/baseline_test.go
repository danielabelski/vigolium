package modkit

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func baselineTestContext(t *testing.T, raw string) *httpmsg.HttpRequestResponse {
	t.Helper()
	service := httpmsg.NewServiceSecure("example.com", 443, true)
	request := httpmsg.NewHttpRequestWithService(service, []byte(raw))
	return httpmsg.NewHttpRequestResponse(request, nil)
}

func TestBaselineRequestKeySeparatesMaterialRequestDimensions(t *testing.T) {
	base := baselineTestContext(t, "POST /api/items?view=full HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nCookie: session=user-a\r\n\r\n{\"id\":1,\"name\":\"a\"}")
	sameSemanticJSON := baselineTestContext(t, "POST /api/items?view=full HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json; charset=utf-8\r\nCookie: session=user-a\r\n\r\n{\"name\":\"a\",\"id\":1}")
	differentIdentity := baselineTestContext(t, "POST /api/items?view=full HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nCookie: session=user-b\r\n\r\n{\"id\":1,\"name\":\"a\"}")
	differentQuery := baselineTestContext(t, "POST /api/items?view=summary HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nCookie: session=user-a\r\n\r\n{\"id\":1,\"name\":\"a\"}")
	differentBody := baselineTestContext(t, "POST /api/items?view=full HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nCookie: session=user-a\r\n\r\n{\"id\":2,\"name\":\"b\"}")

	baseKey := baselineRequestKey(base)
	if got := baselineRequestKey(sameSemanticJSON); got != baseKey {
		t.Fatalf("equivalent JSON serialization got distinct keys:\n%s\n%s", baseKey, got)
	}
	for name, candidate := range map[string]*httpmsg.HttpRequestResponse{
		"identity": differentIdentity,
		"query":    differentQuery,
		"body":     differentBody,
	} {
		if got := baselineRequestKey(candidate); got == baseKey {
			t.Fatalf("different %s reused baseline key %s", name, got)
		}
	}
}

func TestCanonicalBaselineBodyNormalizesFormOrdering(t *testing.T) {
	a := canonicalBaselineBody("application/x-www-form-urlencoded", []byte("b=2&a=1"))
	b := canonicalBaselineBody("application/x-www-form-urlencoded", []byte("a=1&b=2"))
	if a != b {
		t.Fatalf("equivalent form bodies differ: %q != %q", a, b)
	}
}
