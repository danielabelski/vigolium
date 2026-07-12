package waf

import (
	"net/http"
	"testing"
)

func TestEdgeFront(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   string
	}{
		{
			name:   "cloudfront via X-Amz-Cf-Id on a clean 200",
			header: http.Header{"X-Amz-Cf-Id": {"yPIXqfqB5tcNuyZwbvP62uVyKilYTF1y"}, "Via": {"1.1 abc.cloudfront.net (CloudFront)"}},
			want:   "cloudfront",
		},
		{
			name:   "cloudfront via Via header only",
			header: http.Header{"Via": {"1.1 220478e0.cloudfront.net (CloudFront)"}},
			want:   "cloudfront",
		},
		{
			name:   "cloudflare via CF-Ray",
			header: http.Header{"Cf-Ray": {"7d9f0a1b2c3d-SIN"}, "Server": {"cloudflare"}},
			want:   "cloudflare",
		},
		{
			name:   "cloudflare via Server header",
			header: http.Header{"Server": {"cloudflare"}},
			want:   "cloudflare",
		},
		{
			name:   "akamai via X-Akamai-Transformed",
			header: http.Header{"X-Akamai-Transformed": {"9 - 0 pmb=mRUM,1"}},
			want:   "akamai",
		},
		{
			name:   "imperva via X-Iinfo",
			header: http.Header{"X-Iinfo": {"1-234567-890"}},
			want:   "imperva",
		},
		{
			name:   "imperva via X-CDN Incapsula",
			header: http.Header{"X-Cdn": {"Incapsula"}},
			want:   "imperva",
		},
		{
			name:   "sucuri via X-Sucuri-ID",
			header: http.Header{"X-Sucuri-Id": {"15020"}},
			want:   "sucuri",
		},
		{
			name:   "azure front door via X-Azure-Ref",
			header: http.Header{"X-Azure-Ref": {"0abc-def"}},
			want:   "azure_frontdoor",
		},
		{
			name:   "plain origin — no edge",
			header: http.Header{"Server": {"nginx/1.25.3"}, "Content-Type": {"text/html"}},
			want:   "",
		},
		{
			name:   "bare cache passthrough without a fingerprint header — not paced",
			header: http.Header{"X-Cache": {"HIT"}, "Age": {"12"}},
			want:   "",
		},
		{
			name:   "empty header",
			header: http.Header{},
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EdgeFront(tt.header); got != tt.want {
				t.Fatalf("EdgeFront() = %q, want %q", got, tt.want)
			}
		})
	}
}
