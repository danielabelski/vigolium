package jsframework

import "testing"

func TestIsClientBuildArtifact(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want bool
	}{
		// Next.js immutable client build output.
		{"/_next/static/chunks/main-93dbaebda72da021.js", true},
		{"/app/_next/static/chunks/framework.js", true},
		{"/_NEXT/STATIC/chunks/x.js", true}, // case-insensitive
		// Nuxt build output.
		{"/_nuxt/entry.abc123.js", true},
		{"/app/_nuxt/DefaultLayout.js", true},
		// NOT build artifacts — real source / config / app routes.
		{"/next.config.js", false},
		{"/api/users", false},
		{"/_next/data/build/page.json", false}, // _next but not /_next/static/
		{"/static/js/app.js", false},           // CRA static, not _next/_nuxt
		{"/", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsClientBuildArtifact(c.path); got != c.want {
			t.Errorf("IsClientBuildArtifact(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
