package cftbrowser

import (
	"path/filepath"
	"testing"
)

// TestPlatformKeyConsistency ensures IsSupported and PlatformKey agree on the
// current platform without hard-coding which OS/arch the test runs on.
func TestPlatformKeyConsistency(t *testing.T) {
	key, err := PlatformKey()
	if IsSupported() {
		if err != nil {
			t.Errorf("IsSupported()=true but PlatformKey() errored: %v", err)
		}
		if key == "" {
			t.Error("supported platform returned empty key")
		}
	} else {
		if err == nil {
			t.Error("IsSupported()=false but PlatformKey() returned no error")
		}
	}
}

// TestPlatformSupportMatrix pins which OS/arch combinations Chrome for Testing
// publishes a build for. This is the fallback that recovers a host whose system
// browser is broken, so the matrix is load-bearing: notably there is NO
// linux/arm64 build (arm64 Docker, Raspberry Pi, AWS Graviton), so those hosts
// must rely on a working system Chromium — the browser launch ladder skips rod's
// own (also-broken) arm64 auto-download and surfaces an install hint instead.
func TestPlatformSupportMatrix(t *testing.T) {
	supported := map[string]string{
		"linux_amd64":   "chrome-linux64/chrome",
		"darwin_arm64":  "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
		"darwin_amd64":  "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
		"windows_amd64": "chrome-win64/chrome.exe",
		"windows_386":   "chrome-win32/chrome.exe",
	}
	for key, wantBin := range supported {
		p, ok := platforms[key]
		if !ok {
			t.Errorf("expected CfT support for %s", key)
			continue
		}
		if p.BinPath != wantBin {
			t.Errorf("%s BinPath = %q, want %q", key, p.BinPath, wantBin)
		}
	}

	// Explicitly unsupported — no CfT build exists for these.
	for _, key := range []string{"linux_arm64", "linux_386", "windows_arm64", "openbsd_amd64"} {
		if _, ok := platforms[key]; ok {
			t.Errorf("%s should NOT be a supported CfT platform (no upstream build)", key)
		}
	}

	if len(platforms) != len(supported) {
		t.Errorf("platforms map has %d entries, expected exactly %d (matrix drifted)", len(platforms), len(supported))
	}
}

func TestParseMissingLib(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			"typical",
			"./chrome: error while loading shared libraries: libnss3.so: cannot open shared object file",
			"libnss3.so",
		},
		{
			"versioned",
			"error while loading shared libraries: libfoo.so.1: cannot open shared object file: No such file",
			"libfoo.so.1",
		},
		{"no marker", "command not found", ""},
		{"marker without trailing colon", "error while loading shared libraries: libfoo.so", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseMissingLib(tt.output); got != tt.want {
				t.Errorf("parseMissingLib(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}

func TestIsInsideDir(t *testing.T) {
	base := filepath.FromSlash("/tmp/extract-base")
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"child file", filepath.Join(base, "sub", "file.txt"), true},
		{"equal to base", base, true},
		{"parent escape", filepath.Join(base, "..", "escape.txt"), false},
		// Prefix-trick: a sibling whose name starts with base must NOT be
		// considered inside (the impl guards this by requiring a separator).
		{"sibling prefix", filepath.FromSlash("/tmp/extract-base-sibling/file"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isInsideDir(tt.path, base); got != tt.want {
				t.Errorf("isInsideDir(%q, %q) = %v, want %v", tt.path, base, got, tt.want)
			}
		})
	}
}
