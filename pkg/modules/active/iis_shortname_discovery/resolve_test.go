package iis_shortname_discovery

import (
	"strings"
	"testing"
)

func TestGen8dot3(t *testing.T) {
	tests := []struct {
		file, ext        string
		wantReq          bool
		wantF83, wantE83 string
	}{
		{"web", "config", true, "WEB", "CON"},         // web.config (ext>3 => alias)
		{"global", "asax", true, "GLOBAL", "ASA"},     // global.asax (ext=4 => alias)
		{"webadmin", "config", true, "WEBADM", "CON"}, // long file -> 6 chars
		{"default", "aspx", true, "DEFAUL", "ASP"},    // ext "aspx" (4 chars) forces alias
		{"index", "htm", false, "INDEX", "HTM"},       // fits 8.3, no alias required
		{"page", "asp", false, "PAGE", "ASP"},         // fits 8.3
		{"connectionstrings", "config", true, "CONNEC", "CON"},
		{"my file", "txt", true, "MYFILE", "TXT"}, // space removed -> required
	}
	for _, tt := range tests {
		t.Run(tt.file+"."+tt.ext, func(t *testing.T) {
			req, f83, e83 := gen8dot3(tt.file, tt.ext)
			if req != tt.wantReq {
				t.Errorf("gen8dot3(%q,%q) required = %v, want %v", tt.file, tt.ext, req, tt.wantReq)
			}
			if f83 != tt.wantF83 || e83 != tt.wantE83 {
				t.Errorf("gen8dot3(%q,%q) = %q.%q, want %q.%q", tt.file, tt.ext, f83, e83, tt.wantF83, tt.wantE83)
			}
		})
	}
}

func TestChecksumDeterministicHex(t *testing.T) {
	// Checksums must be 4 uppercase hex digits and stable across calls.
	for _, name := range []string{"web.config", "Default.aspx", "backup.zip"} {
		c1 := checksum(name)
		c2 := checksum(name)
		if c1 != c2 {
			t.Errorf("checksum(%q) not deterministic: %q vs %q", name, c1, c2)
		}
		if len(c1) != 4 || strings.ToUpper(c1) != c1 {
			t.Errorf("checksum(%q) = %q, want 4 uppercase hex chars", name, c1)
		}
		for _, r := range c1 {
			if !strings.ContainsRune("0123456789ABCDEF", r) {
				t.Errorf("checksum(%q) = %q has non-hex char %q", name, c1, r)
			}
		}
	}
}

func TestSplitFileExt(t *testing.T) {
	tests := []struct {
		in, file, ext string
	}{
		{"web.config", "web", "config"},
		{"global.asax", "global", "asax"},
		{"backup", "backup", ""},
		{".gitignore", ".gitignore", ""}, // leading dot => extensionless
		{"a.b.c", "a.b", "c"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			f, e := splitFileExt(tt.in)
			if f != tt.file || e != tt.ext {
				t.Errorf("splitFileExt(%q) = %q/%q, want %q/%q", tt.in, f, e, tt.file, tt.ext)
			}
		})
	}
}

func TestNameIndexResolvesWebConfig(t *testing.T) {
	idx := &nameIndex{m: make(map[string][]string), seen: make(map[string]struct{})}
	indexWord(idx, "web.config")
	indexWord(idx, "global.asax")
	indexWord(idx, "default.aspx") // fits 8.3, should NOT be indexed (no alias)

	// web.config -> 8.3 "WEB~1.CON" => fragment file=WEB ext=CON
	got := idx.lookup("WEB", "CON")
	if len(got) == 0 || got[0] != "web.config" {
		t.Errorf("lookup(WEB,CON) = %v, want [web.config]", got)
	}

	// global.asax -> "GLOBAL~1.ASA"
	got = idx.lookup("GLOBAL", "ASA")
	if len(got) == 0 || got[0] != "global.asax" {
		t.Errorf("lookup(GLOBAL,ASA) = %v, want [global.asax]", got)
	}

	// default.aspx fits 8.3 (7-char base, 4-char ext trimmed) => "DEFAULT.ASP"...
	// actually ext "aspx" is 4 chars so an alias IS required; ensure it resolves.
	got = idx.lookup("DEFAUL", "ASP")
	if len(got) == 0 {
		t.Errorf("lookup(DEFAUL,ASP) should resolve default.aspx, got empty")
	}
}

func TestNameIndexChecksumForm(t *testing.T) {
	// A file whose 8.3 base is exactly 6 chars can appear in the Vista+
	// checksummed form (prefix + checksum). Confirm the checksummed key resolves.
	idx := &nameIndex{m: make(map[string][]string), seen: make(map[string]struct{})}
	indexWord(idx, "webadmin.config") // base -> WEBADM (6 chars)

	cks := checksumVariants("webadmin.config")
	if len(cks) == 0 {
		t.Fatal("expected checksum variants")
	}
	// prefix is first 2 chars of the 8.3 base "WEBADM" => "WE"
	found := false
	for _, ck := range cks {
		if got := idx.lookup("WE"+ck, "CON"); len(got) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("checksummed key WE<checksum>.CON did not resolve webadmin.config")
	}
}

func TestClassifyName(t *testing.T) {
	tests := []struct {
		name       string
		wantSens   bool
		wantReason string
	}{
		{"web.config", true, "config"},
		{"appsettings.json", true, "config"},
		{"backup.zip", true, "backup"},
		{"database.mdf", true, "database"},
		{"secret.pfx", true, "secret"},
		{"Login.cs", true, "source"},
		{"logo.png", false, ""},
		{"index.html", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sens, reason := classifyName(tt.name)
			if sens != tt.wantSens || reason != tt.wantReason {
				t.Errorf("classifyName(%q) = %v/%q, want %v/%q", tt.name, sens, reason, tt.wantSens, tt.wantReason)
			}
		})
	}
}

func TestIsResourceStatus(t *testing.T) {
	for _, s := range []int{200, 301, 302, 401, 403, 500} {
		if !isResourceStatus(s) {
			t.Errorf("status %d should count as a resource", s)
		}
	}
	for _, s := range []int{404, 400, 414} {
		if isResourceStatus(s) {
			t.Errorf("status %d should NOT count as a resource", s)
		}
	}
}

func TestResolverIndexLoadsEmbedded(t *testing.T) {
	// The shared index must build from the embedded wordlists without panicking
	// and must contain the high-value static IIS names.
	idx := resolverIndex()
	if idx == nil || len(idx.m) == 0 {
		t.Fatal("resolverIndex() returned empty index")
	}
	if got := idx.lookup("WEB", "CON"); len(got) == 0 {
		t.Error("shared index should resolve WEB.CON to web.config")
	}
}
