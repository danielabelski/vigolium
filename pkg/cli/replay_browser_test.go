package cli

import (
	"maps"
	"testing"
)

func TestBrowserReplayRequest_SessionHeaders(t *testing.T) {
	raw := []byte("GET /x HTTP/1.1\r\nHost: example.com\r\n" +
		"Authorization: Bearer tok\r\nCookie: sid=abc\r\n" +
		"User-Agent: curl/8\r\nX-Other: drop\r\n\r\n")

	method, got := browserReplayRequest(raw)

	if method != "GET" {
		t.Errorf("method = %q, want GET", method)
	}
	want := map[string]string{
		"Authorization": "Bearer tok",
		"Cookie":        "sid=abc",
		"User-Agent":    "curl/8",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d headers %v, want %d %v", len(got), got, len(want), want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("header %q = %q, want %q", k, got[k], v)
		}
	}
	// Only session-bearing headers are forwarded — everything else is dropped.
	if _, ok := got["X-Other"]; ok {
		t.Error("non-session header X-Other should not be forwarded")
	}
}

func TestBrowserReplayRequest_CaseInsensitive(t *testing.T) {
	// HTTP/2-style lowercased header names must still match.
	raw := []byte("GET /x HTTP/1.1\r\nhost: example.com\r\ncookie: sid=z\r\n\r\n")
	if _, got := browserReplayRequest(raw); got["Cookie"] != "sid=z" {
		t.Fatalf("Cookie = %q, want sid=z (got %v)", got["Cookie"], got)
	}
}

func TestBrowserReplayRequest_NoSessionHeaders(t *testing.T) {
	raw := []byte("GET /x HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n")
	if _, got := browserReplayRequest(raw); got != nil {
		t.Errorf("expected nil when no session headers present, got %v", got)
	}
}

func TestBrowserReplayRequest_Empty(t *testing.T) {
	method, got := browserReplayRequest(nil)
	if method != "" || got != nil {
		t.Errorf("expected zero values for an empty request, got %q / %v", method, got)
	}
}

func TestBrowserReplayRequest_Method(t *testing.T) {
	tests := []struct{ name, raw, want string }{
		{"get", "GET /x HTTP/1.1\r\nHost: h\r\n\r\n", "GET"},
		{"post", "POST /x HTTP/1.1\r\nHost: h\r\n\r\n", "POST"},
		{"lowercase is normalized", "post /x HTTP/1.1\r\nHost: h\r\n\r\n", "POST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := browserReplayRequest([]byte(tt.raw)); got != tt.want {
				t.Errorf("method = %q, want %q", got, tt.want)
			}
		})
	}
}

// The overlay is what makes `--with-browser -H 'Cookie: ...'` re-browse as a
// different user, so it must win over the record's own session headers.
func TestBrowserReplayHeaders_OverlayPrecedence(t *testing.T) {
	raw := []byte("GET /x HTTP/1.1\r\nHost: example.com\r\nCookie: sid=stored\r\n\r\n")
	_, headers := browserReplayRequest(raw)

	maps.Copy(headers, map[string]string{"Cookie": "sid=override"})

	if headers["Cookie"] != "sid=override" {
		t.Fatalf("Cookie = %q, want the overlay value sid=override", headers["Cookie"])
	}
}
