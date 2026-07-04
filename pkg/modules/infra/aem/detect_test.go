package aem

import "testing"

func hdr(m map[string]string) func(string) string {
	return func(name string) string { return m[name] }
}

func TestMatchResponseStrongBody(t *testing.T) {
	ok, sig := MatchResponse(200, hdr(nil), `<html>Welcome to Adobe Experience Manager</html>`)
	if !ok {
		t.Fatalf("expected AEM match on welcome text")
	}
	if len(sig) == 0 {
		t.Fatalf("expected signals")
	}
}

func TestMatchResponseServerHeader(t *testing.T) {
	ok, _ := MatchResponse(200, hdr(map[string]string{"Server": "Communique/4.0.0"}), "irrelevant body")
	if !ok {
		t.Fatalf("expected AEM match on Communique Server header")
	}
}

func TestMatchResponseFelixChallenge(t *testing.T) {
	ok, _ := MatchResponse(401, hdr(map[string]string{"WWW-Authenticate": `Basic realm="OSGi Management Console"`}), "")
	if !ok {
		t.Fatalf("expected AEM match on OSGi console challenge")
	}
}

func TestMatchResponseSingleMediumInsufficient(t *testing.T) {
	// One medium marker alone must not fire (a proxied page could echo /content/dam/).
	ok, _ := MatchResponse(200, hdr(nil), `<a href="/content/dam/foo.png">img</a>`)
	if ok {
		t.Fatalf("single medium marker should not confirm AEM")
	}
}

func TestMatchResponseTwoMediumConfirms(t *testing.T) {
	ok, _ := MatchResponse(200, hdr(nil), `href="/etc/designs/site/x.css" src="/content/dam/y.png"`)
	if !ok {
		t.Fatalf("two co-occurring medium markers should confirm AEM")
	}
}

func TestMatchResponseNonAEM(t *testing.T) {
	ok, _ := MatchResponse(200, hdr(map[string]string{"Server": "nginx"}), `<html><body>hello world</body></html>`)
	if ok {
		t.Fatalf("plain nginx page must not match AEM")
	}
}

func TestExtractVersion(t *testing.T) {
	cases := []struct {
		server string
		want   string
	}{
		{"Communique/4.2.0", "4.2.0"},
		{"Day-Servlet-Engine/4.1.24", "4.1.24"},
		{"CQ5/5.6.1", "5.6.1"},
		{"Apache", ""},
		{"nginx/1.25.3", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := ExtractVersion(hdr(map[string]string{"Server": c.server}))
		if got != c.want {
			t.Errorf("ExtractVersion(Server=%q) = %q, want %q", c.server, got, c.want)
		}
	}
	if got := ExtractVersion(nil); got != "" {
		t.Errorf("nil headerGet should return empty, got %q", got)
	}
}
