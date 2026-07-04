package iis_cookieless_source_disclosure

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestConfirmArtifactConfig(t *testing.T) {
	realConfig := `<?xml version="1.0"?><configuration><system.web><machineKey validationKey="AAAA" /></system.web></configuration>`
	if ok, ev := confirmArtifact(kindConfig, realConfig); !ok || len(ev) == 0 {
		t.Errorf("real web.config should confirm, got ok=%v ev=%v", ok, ev)
	}

	// An HTML error page merely mentioning web.config must NOT confirm.
	fake := `<html><body>Server Error: could not read configuration file web.config</body></html>`
	if ok, _ := confirmArtifact(kindConfig, fake); ok {
		t.Error("HTML error page mentioning web.config should not confirm")
	}

	// Missing config elements must not confirm.
	bare := `<configuration></configuration>`
	if ok, _ := confirmArtifact(kindConfig, bare); ok {
		t.Error("bare <configuration> with no elements should not confirm")
	}
}

func TestConfirmArtifactJSON(t *testing.T) {
	appsettings := `{ "ConnectionStrings": { "Default": "Server=.;Database=app;" }, "Logging": {} }`
	if ok, _ := confirmArtifact(kindConfig, appsettings); !ok {
		t.Error("appsettings.json with ConnectionStrings should confirm")
	}
	htmlWithWord := `<html>connectionstrings are configured elsewhere</html>`
	if ok, _ := confirmArtifact(kindConfig, htmlWithWord); ok {
		t.Error("HTML mentioning connectionstrings should not confirm as JSON config")
	}
}

func TestConfirmArtifactSource(t *testing.T) {
	asax := `<%@ Application Codebehind="Global.asax.cs" Inherits="MyApp.Global" %>`
	if ok, _ := confirmArtifact(kindSource, asax); !ok {
		t.Error("global.asax application directive should confirm as source")
	}
	if ok, _ := confirmArtifact(kindSource, "just some text"); ok {
		t.Error("plain text should not confirm as source")
	}
}

func TestConfirmArtifactBinary(t *testing.T) {
	pe := "MZ\x90\x00\x03"
	if ok, _ := confirmArtifact(kindBinary, pe); !ok {
		t.Error("MZ header should confirm as binary")
	}
	if ok, _ := confirmArtifact(kindBinary, "<html>"); ok {
		t.Error("HTML should not confirm as binary")
	}
}

func TestBuildVector(t *testing.T) {
	// Root file: shapes 0-2 apply, shape 3 (in-segment split) does not.
	if p, ok := buildVector("web.config", 0, "abc"); !ok || !strings.Contains(p, "(S(abc))") || !strings.HasSuffix(p, "web.config") {
		t.Errorf("shape 0 for web.config = %q ok=%v", p, ok)
	}
	if _, ok := buildVector("web.config", 3, "abc"); ok {
		t.Error("shape 3 should not apply to a root file with no directory")
	}

	// Path with a directory: shape 3 splits the first segment.
	p, ok := buildVector("bin/MyApp.dll", 3, "x")
	if !ok || !strings.Contains(p, "(S(x))") || !strings.HasSuffix(p, "MyApp.dll") {
		t.Errorf("shape 3 for bin/MyApp.dll = %q ok=%v", p, ok)
	}
	// The token must land inside the "bin" segment, not before it.
	if strings.HasPrefix(p, "/(S(x))") {
		t.Errorf("shape 3 should split the segment, got leading token: %q", p)
	}
}

func TestExtOfRel(t *testing.T) {
	cases := map[string]string{
		"web.config":    ".config",
		"bin/MyApp.dll": ".dll",
		"global.asax":   ".asax",
		"noext":         "",
	}
	for in, want := range cases {
		if got := extOfRel(in); got != want {
			t.Errorf("extOfRel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanProcessGating(t *testing.T) {
	m := New()
	if m.CanProcess(nil) {
		t.Error("CanProcess(nil) should be false")
	}

	iis := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, map[string]string{"Server": "Microsoft-IIS/10.0"}, "OK"))
	req, _ := httpmsg.ParseRawRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if !m.CanProcess(req.WithResponse(iis)) {
		t.Error("CanProcess should be true for IIS response")
	}

	nginx := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, map[string]string{"Server": "nginx"}, "OK"))
	if m.CanProcess(req.WithResponse(nginx)) {
		t.Error("CanProcess should be false for nginx response")
	}
}
