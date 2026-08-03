package fuzz

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const baseGET = "GET /api?id=1 HTTP/1.1\r\nHost: target.test\r\nAccept: */*\r\n\r\n"

func TestOverridesMethod(t *testing.T) {
	out, err := Overrides{Method: "post"}.Apply([]byte(baseGET))
	if err != nil {
		t.Fatal(err)
	}
	if got := methodOf(t, out); got != "POST" {
		t.Fatalf("method = %q, want POST", got)
	}
	if !strings.Contains(string(out), "/api?id=1 HTTP/1.1") {
		t.Errorf("request target lost:\n%s", out)
	}
}

func TestOverridesHeadersAddAndReplace(t *testing.T) {
	out, err := Overrides{Headers: []string{"X-New: added", "Accept: application/json"}}.Apply([]byte(baseGET))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "X-New: added") {
		t.Errorf("added header missing:\n%s", s)
	}
	if !strings.Contains(s, "Accept: application/json") || strings.Contains(s, "Accept: */*") {
		t.Errorf("existing header not replaced:\n%s", s)
	}
}

func TestOverridesRejectsMalformedHeader(t *testing.T) {
	if _, err := (Overrides{Headers: []string{"nocolon"}}).Apply([]byte(baseGET)); err == nil {
		t.Fatal("expected an error for a header without a colon")
	}
}

func TestOverridesBodySetsContentLength(t *testing.T) {
	out, err := Overrides{Method: "POST", Body: "a=1&b=2"}.Apply([]byte(baseGET))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "Content-Length: 7") {
		t.Errorf("Content-Length not set:\n%s", s)
	}
	if !strings.HasSuffix(s, "\r\n\r\na=1&b=2") {
		t.Errorf("body not appended after the terminator:\n%s", s)
	}
}

func TestSetBodyReplacesExistingBodyAndLength(t *testing.T) {
	orig := "POST /x HTTP/1.1\r\nHost: t.test\r\nContent-Length: 3\r\n\r\nold"
	replaced, err := httpmsg.SetBodyString([]byte(orig), "brand-new-body")
	if err != nil {
		t.Fatal(err)
	}
	out := string(replaced)
	if !strings.Contains(out, "Content-Length: 14") {
		t.Errorf("Content-Length not refreshed:\n%s", out)
	}
	if strings.Contains(out, "old") {
		t.Errorf("old body survived:\n%s", out)
	}
	// A second Content-Length would be a smuggling-shaped request, and is
	// exactly what the append-only utils helper used to produce here.
	if n := strings.Count(out, "Content-Length:"); n != 1 {
		t.Errorf("got %d Content-Length headers, want 1:\n%s", n, out)
	}
}

func TestOverridesDoNotDuplicateHeaders(t *testing.T) {
	out, err := Overrides{Headers: []string{"Accept: application/json", "Accept: text/html"}}.Apply([]byte(baseGET))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if n := strings.Count(s, "Accept:"); n != 1 {
		t.Errorf("got %d Accept headers, want 1:\n%s", n, s)
	}
	if !strings.Contains(s, "Accept: text/html") {
		t.Errorf("last -H should win:\n%s", s)
	}
}

func TestOverridesEmptyIsIdentity(t *testing.T) {
	out, err := Overrides{}.Apply([]byte(baseGET))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != baseGET {
		t.Errorf("empty overrides changed the request:\n%s", out)
	}
}

// A header the request doesn't carry is the interesting case for
// X-Forwarded-For style probes, so --fuzz-header injects it instead of
// refusing.
func TestResolvePositionsInjectsAbsentHeader(t *testing.T) {
	positions, err := ResolvePositions([]byte(baseGET), Selectors{HeaderNames: []string{"X-Forwarded-For"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(positions) != 1 {
		t.Fatalf("got %d positions, want 1", len(positions))
	}
	if positions[0].Label != "HEADER" || positions[0].Name != "X-Forwarded-For" {
		t.Fatalf("unexpected position %+v", positions[0])
	}

	built := string(BuildAt(positions[0], []byte(baseGET), "127.0.0.1"))
	if !strings.Contains(built, "X-Forwarded-For: 127.0.0.1") {
		t.Errorf("header not injected:\n%s", built)
	}
	if !strings.Contains(built, "Host: target.test") {
		t.Errorf("original headers lost:\n%s", built)
	}
}

func TestResolvePositionsUsesExistingHeaderPoint(t *testing.T) {
	positions, err := ResolvePositions([]byte(baseGET), Selectors{HeaderNames: []string{"Accept"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(positions) != 1 {
		t.Fatalf("got %d positions, want 1", len(positions))
	}
	if positions[0].kind != kindInsertionPoint {
		t.Errorf("existing header should use an insertion point, got kind %v", positions[0].kind)
	}
}

// methodOf reads a request's verb through the shared parser.
func methodOf(t *testing.T, raw []byte) string {
	t.Helper()
	method, err := httpmsg.GetMethod(raw)
	if err != nil {
		return ""
	}
	return method
}
