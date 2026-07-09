package discovery

import (
	"net/url"
	"testing"
)

func TestIsImmutableAssetDir(t *testing.T) {
	tests := []struct {
		name     string
		urlPath  string
		expected bool
	}{
		// Next.js immutable build output - should be skipped
		{name: "next static root", urlPath: "/_next/static/", expected: true},
		{name: "next static chunks", urlPath: "/_next/static/chunks/", expected: true},
		{name: "next static chunks file", urlPath: "/_next/static/chunks/main-5cf96b0d57f7f579.js", expected: true},
		{name: "next static build-id chunks", urlPath: "/_next/static/346AbcWMwZdg-2sEdGQLv/_buildManifest.js", expected: true},

		// Nuxt / SvelteKit immutable output - should be skipped
		{name: "nuxt dir", urlPath: "/_nuxt/", expected: true},
		{name: "nuxt entry", urlPath: "/_nuxt/entry.abc123.js", expected: true},
		{name: "sveltekit immutable", urlPath: "/_app/immutable/chunks/index.abc.js", expected: true},

		// Nested under a subpath mount - still an immutable build dir
		{name: "subpath mounted next static", urlPath: "/app/_next/static/chunks/x.js", expected: true},
		{name: "uppercase marker", urlPath: "/_NEXT/STATIC/chunks/x.js", expected: true},

		// Generic /static/* is NOT a framework marker - old/hand-rolled apps store
		// real, individually-authored assets there, so it must remain discoverable.
		// (Content-hash detection handles the case where it holds bundles.)
		{name: "generic static js", urlPath: "/static/js/main.abc123.chunk.js", expected: false},
		{name: "generic static css", urlPath: "/static/css/app.css", expected: false},
		{name: "generic static media", urlPath: "/static/media/logo.svg", expected: false},

		// Real app routes / endpoints - must NOT be skipped
		{name: "api endpoint", urlPath: "/api/contracts", expected: false},
		{name: "next non-static internal", urlPath: "/_next/data/build/index.json", expected: false},
		{name: "next image endpoint", urlPath: "/_next/image", expected: false},
		{name: "next root dir", urlPath: "/_next/", expected: false},
		{name: "generic static dir", urlPath: "/static/", expected: false},
		{name: "static uploads", urlPath: "/static/uploads/report.pdf", expected: false},
		{name: "admin path", urlPath: "/admin/settings/", expected: false},
		{name: "root", urlPath: "/", expected: false},
		{name: "empty", urlPath: "", expected: false},
		{name: "assets dir", urlPath: "/assets/js/app.js", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isImmutableAssetDir(tt.urlPath); got != tt.expected {
				t.Errorf("isImmutableAssetDir(%q) = %v, want %v", tt.urlPath, got, tt.expected)
			}
		})
	}
}

func TestLooksLikeHashedAsset(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected bool
	}{
		// Real content-hashed bundles observed in the wild (Next.js/webpack)
		{name: "named + long hash", filename: "main-5cf96b0d57f7f579.js", expected: true},
		{name: "framework chunk", filename: "framework-bb5c596eafb42b22.js", expected: true},
		{name: "webpack runtime", filename: "webpack-c69d5d69393e8bf3.js", expected: true},
		{name: "polyfills", filename: "polyfills-c67a75d1b6f99dc8.js", expected: true},
		{name: "numeric id + hash", filename: "938-50137dfb3187f5b2.js", expected: true},
		{name: "short numeric id + hash", filename: "3-b9c1c6ace7d20224.js", expected: true},
		{name: "double hash", filename: "29107295-1494f237b9e407ad.js", expected: true},
		{name: "hex prefix + hash", filename: "2b7b2d2a-8e49cd503b1e459f.js", expected: true},
		{name: "underscore prefix", filename: "_app-878fbfe78c3732ea.js", expected: true},
		{name: "page chunk", filename: "index-8344719d9560db8f.js", expected: true},
		{name: "route chunk", filename: "new-7ba71b309a9ae7d9.js", expected: true},
		{name: "cra dotted hash", filename: "main.073c9bfa.chunk.js", expected: true},
		{name: "hashed css", filename: "styles-a1b2c3d4e5.css", expected: true},
		{name: "hashed mjs", filename: "entry-deadbeef12.mjs", expected: true},
		{name: "hashed sourcemap", filename: "main-5cf96b0d57f7f579.js.map", expected: true},

		// Hand-authored / stable filenames - must NOT be flagged
		{name: "plain main", filename: "main.js", expected: false},
		{name: "plain app", filename: "app.js", expected: false},
		{name: "vendor", filename: "vendor.js", expected: false},
		{name: "jquery version", filename: "jquery-3.6.0.min.js", expected: false},
		{name: "bootstrap bundle", filename: "bootstrap.bundle.min.js", expected: false},
		{name: "d3 versioned", filename: "d3.v7.min.js", expected: false},
		{name: "next build manifest", filename: "_buildManifest.js", expected: false},
		{name: "next ssg manifest", filename: "_ssgManifest.js", expected: false},
		{name: "decimal timestamp", filename: "build-20240115.js", expected: false},
		{name: "short hex", filename: "app-abc123.js", expected: false},
		{name: "letters no hex", filename: "analytics-abcdefgh.js", expected: false},
		{name: "not a bundle ext", filename: "photo-5cf96b0d57f7f579.png", expected: false},
		{name: "json data", filename: "data-5cf96b0d57f7f579.json", expected: false},
		{name: "no extension", filename: "5cf96b0d57f7f579", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeHashedAsset(tt.filename); got != tt.expected {
				t.Errorf("looksLikeHashedAsset(%q) = %v, want %v", tt.filename, got, tt.expected)
			}
		})
	}
}

// dirKey computes the hashedAssetDirs lookup key via the shared directoryKey helper.
func dirKey(t *testing.T, e *Engine, dirURL string) string {
	t.Helper()
	return e.directoryKey(mustParse(t, dirURL))
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestRecordHashedAssetParent(t *testing.T) {
	e := &Engine{}

	// A hashed bundle marks its immediate parent directory.
	e.recordHashedAssetParent(mustParse(t, "https://x.test/_next/static/chunks/main-5cf96b0d57f7f579.js"))
	if !e.dirHoldsHashedAssets(dirKey(t, e, "https://x.test/_next/static/chunks/")) {
		t.Error("hashed bundle should mark its parent dir as a hashed-asset dir")
	}

	// A deeper hashed bundle marks its own immediate parent, not shallower ancestors.
	e.recordHashedAssetParent(mustParse(t, "https://x.test/assets/pages/index-8344719d9560db8f.js"))
	if !e.dirHoldsHashedAssets(dirKey(t, e, "https://x.test/assets/pages/")) {
		t.Error("deeper hashed bundle should mark its immediate parent dir")
	}
	if e.dirHoldsHashedAssets(dirKey(t, e, "https://x.test/assets/")) {
		t.Error("shallower ancestor of a hashed bundle must NOT be marked")
	}

	// A plain, hand-authored file must not mark its directory.
	e.recordHashedAssetParent(mustParse(t, "https://x.test/js/app.js"))
	if e.dirHoldsHashedAssets(dirKey(t, e, "https://x.test/js/")) {
		t.Error("plain file must not mark its dir as a hashed-asset dir")
	}

	// A hashed file at the site root must not suppress root recursion.
	e.recordHashedAssetParent(mustParse(t, "https://x.test/main-5cf96b0d57f7f579.js"))
	if e.dirHoldsHashedAssets(dirKey(t, e, "https://x.test/")) {
		t.Error("hashed file at root must NOT mark the root dir")
	}
}
