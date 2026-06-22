package lfi_path_traversal

import (
	"testing"
)

func TestMatchFileParams(t *testing.T) {
	tests := []struct {
		name     string
		param    string
		expected bool
	}{
		{"exact match", "file", true},
		{"contains file", "filename", true},
		{"contains path", "basepath", true},
		{"download", "download", true},
		{"unrelated", "username", false},
		{"empty", "", false},
		{"camelCase", "filePath", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchFileParams(tt.param)
			if got != tt.expected {
				t.Errorf("matchFileParams(%q) = %v, want %v", tt.param, got, tt.expected)
			}
		})
	}
}

func TestLooksLikeFilePath(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"relative path", "../config.xml", true},
		{"absolute path", "/etc/passwd", true},
		{"dot-slash", "./page.html", true},
		{"html extension", "index.html", true},
		{"txt extension", "readme.txt", true},
		{"no path", "hello", false},
		{"numeric", "12345", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeFilePath(tt.value)
			if got != tt.expected {
				t.Errorf("looksLikeFilePath(%q) = %v, want %v", tt.value, got, tt.expected)
			}
		})
	}
}

// The structural confirmers themselves (passwd/win.ini/nginx, incl. the
// Cloudflare cf-beacon block-page rejection) are unit-tested in their shared
// home: pkg/modules/shared/filesig. Here we cover only this module's wiring and
// the full-scan WAF-block regression (see scan_detect_test.go).
