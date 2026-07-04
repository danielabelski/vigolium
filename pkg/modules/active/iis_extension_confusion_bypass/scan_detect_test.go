package iis_extension_confusion_bypass

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestIsScriptPath(t *testing.T) {
	yes := []string{"/default.aspx", "/svc/Api.asmx", "/handler.ashx", "/Global.asax", "/a/b/Page.ASPX?x=1"}
	no := []string{"/index.html", "/style.css", "/img.png", "/", "/api/users"}
	for _, p := range yes {
		if !isScriptPath(p) {
			t.Errorf("isScriptPath(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if isScriptPath(p) {
			t.Errorf("isScriptPath(%q) = true, want false", p)
		}
	}
}

func TestHasSourceMarkers(t *testing.T) {
	src := `<%@ Page Language="C#" CodeBehind="Default.aspx.cs" Inherits="App.Default" %><html>`
	if !hasSourceMarkers(src) {
		t.Error("aspx source directive should be detected")
	}
	if hasSourceMarkers("<html><body>Welcome, user!</body></html>") {
		t.Error("rendered HTML should not be detected as source")
	}
	if hasSourceMarkers("") {
		t.Error("empty body should not be detected as source")
	}
}

func TestApplyAccessShapeFile(t *testing.T) {
	path := "/admin/secret.aspx"
	seen := map[string]bool{}
	for s := 0; s < numAccessShapes; s++ {
		cand, label, ok := applyAccessShape(path, s)
		if !ok {
			t.Fatalf("shape %d should apply to a file path", s)
		}
		if cand == path {
			t.Errorf("shape %d (%s) did not modify the path", s, label)
		}
		if seen[cand] {
			t.Errorf("shape %d produced a duplicate candidate %q", s, cand)
		}
		seen[cand] = true
	}
	// trailing dot form
	if c, _, _ := applyAccessShape(path, 0); c != path+"." {
		t.Errorf("shape 0 = %q, want trailing dot", c)
	}
	// ADS form
	if c, _, _ := applyAccessShape(path, 2); !strings.Contains(c, "::$INDEX_ALLOCATION") {
		t.Errorf("shape 2 = %q, want ::$INDEX_ALLOCATION", c)
	}
}

func TestApplyAccessShapeDir(t *testing.T) {
	path := "/admin/"
	c, _, ok := applyAccessShape(path, 0)
	if !ok || c != "/admin./" {
		t.Errorf("dir trailing-dot = %q ok=%v, want /admin./", c, ok)
	}
	c, _, ok = applyAccessShape(path, 2)
	if !ok || !strings.HasSuffix(c, "::$INDEX_ALLOCATION/") {
		t.Errorf("dir index-allocation = %q ok=%v", c, ok)
	}

	// Root path must not produce a candidate.
	if _, _, ok := applyAccessShape("/", 2); ok {
		t.Error("root path should not yield an access-bypass candidate")
	}
}

func TestApplyAccessShapeDeterministic(t *testing.T) {
	// Same (path, shape) must be reproducible so decoy control matches.
	for s := 0; s < numAccessShapes; s++ {
		a, _, _ := applyAccessShape("/x/y.aspx", s)
		b, _, _ := applyAccessShape("/x/y.aspx", s)
		if a != b {
			t.Errorf("shape %d not deterministic: %q vs %q", s, a, b)
		}
	}
}

func TestPathExt(t *testing.T) {
	cases := map[string]string{
		"/admin/secret.aspx": ".aspx",
		"/admin/":            "",
		"/a/b.ashx?x=1":      ".ashx",
		"/noext":             "",
	}
	for in, want := range cases {
		if got := pathExt(in); got != want {
			t.Errorf("pathExt(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanProcessGating(t *testing.T) {
	m := New()
	if m.CanProcess(nil) {
		t.Error("CanProcess(nil) should be false")
	}
	req, _ := httpmsg.ParseRawRequest("GET /default.aspx HTTP/1.1\r\nHost: example.com\r\n\r\n")
	iis := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, map[string]string{"X-AspNet-Version": "4.0.30319"}, "OK"))
	if !m.CanProcess(req.WithResponse(iis)) {
		t.Error("CanProcess should be true for ASP.NET response")
	}
	apache := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, map[string]string{"Server": "Apache"}, "OK"))
	if m.CanProcess(req.WithResponse(apache)) {
		t.Error("CanProcess should be false for Apache response")
	}
}
