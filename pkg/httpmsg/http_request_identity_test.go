package httpmsg

import "testing"

func TestHttpRequestIdentityFingerprint(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "anonymous", raw: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{name: "cookie", raw: "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=user-a\r\n\r\n"},
		{name: "authorization", raw: "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer token-a\r\n\r\n"},
	}

	fingerprints := make(map[string]string, len(tests))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := NewHttpRequest([]byte(test.raw))
			first := request.IdentityFingerprint()
			second := request.IdentityFingerprint()
			if first != second {
				t.Fatalf("fingerprint is not stable: %q != %q", first, second)
			}
			if test.name == "anonymous" && first != "anonymous" {
				t.Fatalf("anonymous request fingerprint = %q", first)
			}
			if test.name != "anonymous" && (first == "anonymous" || first == "session=user-a" || first == "Bearer token-a") {
				t.Fatalf("credential was not represented by an opaque fingerprint: %q", first)
			}
			fingerprints[test.name] = first
		})
	}

	if fingerprints["cookie"] == fingerprints["authorization"] {
		t.Fatal("different credentials must produce different fingerprints")
	}

	changedCookie := NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=user-b\r\n\r\n"))
	if changedCookie.IdentityFingerprint() == fingerprints["cookie"] {
		t.Fatal("different cookie identities must not collide")
	}
}

func TestNilHttpRequestIdentityFingerprint(t *testing.T) {
	var request *HttpRequest
	if got := request.IdentityFingerprint(); got != "anonymous" {
		t.Fatalf("nil request fingerprint = %q, want anonymous", got)
	}
}

func TestHttpRequestIdentityFingerprintIgnoresNonIdentityCookieChurn(t *testing.T) {
	preferenceA := NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: theme=dark; _ga=one\r\n\r\n"))
	preferenceB := NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: _ga=two; theme=light\r\n\r\n"))
	if preferenceA.IdentityFingerprint() != "anonymous" || preferenceB.IdentityFingerprint() != "anonymous" {
		t.Fatal("preference and analytics cookies must not create scanner identities")
	}

	sessionA := NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: theme=dark; session=user-a; _ga=one\r\n\r\n"))
	sessionAReordered := NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: _ga=changed; session=user-a; theme=light\r\n\r\n"))
	if sessionA.IdentityFingerprint() != sessionAReordered.IdentityFingerprint() {
		t.Fatal("non-identity cookie changes and ordering must not split one session")
	}

	unknownA := NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: app_opaque=one\r\n\r\n"))
	unknownB := NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: app_opaque=two\r\n\r\n"))
	if unknownA.IdentityFingerprint() == "anonymous" || unknownA.IdentityFingerprint() == unknownB.IdentityFingerprint() {
		t.Fatal("unknown application cookies must conservatively separate possible user identities")
	}
}
