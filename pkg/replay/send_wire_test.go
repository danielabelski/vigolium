package replay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestSendRawPreservesRequestTarget pins the bytes that leave the wire. The
// send path rebuilds the request URL to retarget it at the caller's
// scheme/host, and it used to rebuild from the *decoded* path — which
// normalized percent-escapes out of the request line. Encoded slashes and
// dot-segments are the payload for path-normalization and traversal probes, so
// losing them turns a real finding into a silent false negative.
func TestSendRawPreservesRequestTarget(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RequestURI
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	host, port := splitAddr(t, srv.Listener.Addr().String())
	client := NewDefaultClient(nil, 0)

	cases := []struct {
		name   string
		target string
	}{
		{"encoded slash", "/a/..%2fadmin?q=1"},
		{"encoded dots", "/%2e%2e/x"},
		{"double encoded slash", "/a/..%252fadmin"},
		{"matrix param dot segment", "/a/..;/admin"},
		{"literal dot segments", "/a/../admin"},
		{"encoded semicolon", "/a/..%3b/admin"},
		{"double slash", "//evil.example/path"},
		{"encoded query preserved", "/a?q=%2527"},
		{"encoded space in path", "/a%20b/c"},
		{"plus in query", "/a?q=a+b"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen = ""
			raw := "GET " + tc.target + " HTTP/1.1\r\nHost: placeholder\r\n\r\n"
			sum := SendRaw(context.Background(), client, []byte(raw), "http", host, port, true, 0)
			if sum.Error != "" {
				t.Fatalf("send failed: %s", sum.Error)
			}
			if seen != tc.target {
				t.Errorf("request target mangled on the wire:\n  sent:   %q\n  server: %q", tc.target, seen)
			}
		})
	}
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		t.Fatalf("bad addr %q", addr)
	}
	port, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		t.Fatalf("bad port in %q: %v", addr, err)
	}
	return addr[:i], port
}
