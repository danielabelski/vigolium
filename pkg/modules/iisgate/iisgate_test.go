package iisgate

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestRespLooksIIS(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"Microsoft-IIS server header", map[string]string{"Server": "Microsoft-IIS/10.0"}, true},
		{"Microsoft-IIS lowercase", map[string]string{"Server": "microsoft-iis/8.5"}, true},
		{"X-AspNet-Version header", map[string]string{"X-AspNet-Version": "4.0.30319"}, true},
		{"X-AspNetMvc-Version header", map[string]string{"X-AspNetMvc-Version": "5.2"}, true},
		{"X-Powered-By ASP.NET", map[string]string{"X-Powered-By": "ASP.NET"}, true},
		{"Apache server", map[string]string{"Server": "Apache/2.4.41"}, false},
		{"Nginx server", map[string]string{"Server": "nginx/1.18.0"}, false},
		{"No headers", map[string]string{}, false},
		{"X-Powered-By PHP", map[string]string{"X-Powered-By": "PHP/7.4"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, tt.headers, "OK"))
			if got := RespLooksIIS(resp); got != tt.want {
				t.Errorf("RespLooksIIS() = %v, want %v", got, tt.want)
			}
		})
	}
	if RespLooksIIS(nil) {
		t.Error("RespLooksIIS(nil) should be false")
	}
}

func TestLooksLikeIIS(t *testing.T) {
	req, _ := httpmsg.ParseRawRequest("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Header path.
	iis := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, map[string]string{"Server": "Microsoft-IIS/10.0"}, "OK"))
	if !LooksLikeIIS(req.WithResponse(iis), nil, "example.com") {
		t.Error("IIS Server header should pass the passive gate")
	}

	// TechStack path.
	nginx := httpmsg.NewHttpResponse(httpmsg.BuildRawResponse(200, map[string]string{"Server": "nginx"}, "OK"))
	ctx := req.WithResponse(nginx)
	scanCtx := &modkit.ScanContext{TechStack: modkit.NewTechRegistry()}
	if LooksLikeIIS(ctx, scanCtx, "example.com") {
		t.Error("should not look like IIS before tech marked")
	}
	scanCtx.TechStack.Mark("example.com", "aspnet")
	if !LooksLikeIIS(ctx, scanCtx, "example.com") {
		t.Error("should look like IIS after aspnet tech marked")
	}
}

func TestDecideIIS(t *testing.T) {
	home := "<html><body>Welcome to Contoso</body></html>"
	notFound := "<html><body>404 - File or directory not found.</body></html>"

	tests := []struct {
		name           string
		base, tok, rnd resp
		want           bool
	}{
		{
			name: "genuine ASP.NET: token stripped, random 404",
			base: resp{200, home, true},
			tok:  resp{200, home, true}, // (S(x)) stripped -> same as home
			rnd:  resp{404, notFound, true},
			want: true,
		},
		{
			name: "non-IIS: token segment 404s (not stripped)",
			base: resp{200, home, true},
			tok:  resp{404, notFound, true},
			rnd:  resp{404, notFound, true},
			want: false,
		},
		{
			name: "catch-all: random path returns the same page as base",
			base: resp{200, home, true},
			tok:  resp{200, home, true},
			rnd:  resp{200, home, true}, // everything echoes home -> can't distinguish
			want: false,
		},
		{
			name: "transient failure on token probe",
			base: resp{200, home, true},
			tok:  resp{0, "", false},
			rnd:  resp{404, notFound, true},
			want: false,
		},
		{
			name: "base probe failed",
			base: resp{0, "", false},
			tok:  resp{200, home, true},
			rnd:  resp{404, notFound, true},
			want: false,
		},
		{
			name: "token status differs from base",
			base: resp{200, home, true},
			tok:  resp{302, home, true},
			rnd:  resp{404, notFound, true},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decideIIS(tt.base, tt.tok, tt.rnd); got != tt.want {
				t.Errorf("decideIIS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAnchorable(t *testing.T) {
	for _, s := range []int{200, 301, 302, 401, 403} {
		if !anchorable(s) {
			t.Errorf("status %d should be anchorable", s)
		}
	}
	for _, s := range []int{404, 500, 400, 0} {
		if anchorable(s) {
			t.Errorf("status %d should not be anchorable", s)
		}
	}
}

func TestConfirmIISBehaviorNilSafe(t *testing.T) {
	if ConfirmIISBehavior("example.com", nil, nil) {
		t.Error("nil ctx/client should return false, not panic")
	}
}
