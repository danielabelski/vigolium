package cli

import (
	"strings"
	"testing"
)

// TestParseExportFormats locks in the --format grammar: comma-separated, alias
// normalized, duplicate-collapsed, order-preserving, and a hard error on an
// unknown name (never a silent skip, which would drop a format the user asked
// for and report success).
func TestParseExportFormats(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr string
	}{
		{name: "single", raw: "jsonl", want: []string{"jsonl"}},
		{name: "multiple", raw: "html,bundle,markdown", want: []string{"html", "bundle", "markdown"}},
		{name: "order preserved", raw: "markdown,html", want: []string{"markdown", "html"}},
		{name: "aliases normalized", raw: "md,gz", want: []string{"markdown", "bundle"}},
		{name: "whitespace tolerated", raw: " html , md ", want: []string{"html", "markdown"}},
		{name: "case insensitive", raw: "HTML,PDF", want: []string{"html", "pdf"}},
		{name: "duplicates collapsed", raw: "html,html", want: []string{"html"}},
		{name: "alias dupes collapse onto canonical", raw: "markdown,md", want: []string{"markdown"}},
		{name: "empty segments skipped", raw: "html,,jsonl", want: []string{"html", "jsonl"}},
		{name: "every format", raw: "html,report,pdf,jsonl,markdown,bundle,fs",
			want: []string{"html", "report", "pdf", "jsonl", "markdown", "bundle", "fs"}},
		{name: "unknown is an error", raw: "html,nope", wantErr: `unsupported format "nope"`},
		{name: "whole-string value is not a format", raw: "html;bundle", wantErr: `unsupported format "html;bundle"`},
		{name: "empty is an error", raw: "", wantErr: "requires at least one format"},
		{name: "only separators is an error", raw: ",,", wantErr: "requires at least one format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specs, err := parseExportFormats(tt.raw)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseExportFormats(%q) = nil error, want %q", tt.raw, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseExportFormats(%q) error = %q, want it to contain %q", tt.raw, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExportFormats(%q) unexpected error: %v", tt.raw, err)
			}
			got := exportFormatNames(specs)
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("parseExportFormats(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// TestParseExportFormatsKeepsRawToken verifies the typed spelling survives
// normalization, so an error message quotes what the user wrote rather than the
// canonical name they never used.
func TestParseExportFormatsKeepsRawToken(t *testing.T) {
	specs, err := parseExportFormats("gz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if specs[0].format != "bundle" {
		t.Errorf("format = %q, want bundle", specs[0].format)
	}
	if specs[0].raw != "gz" {
		t.Errorf("raw = %q, want gz", specs[0].raw)
	}
}

// TestAssignExportPathsSingleFormatVerbatim pins the backward-compatible
// contract: with one format, -o is used exactly as given — no extension is
// added, stripped, or corrected.
func TestAssignExportPathsSingleFormatVerbatim(t *testing.T) {
	for _, base := range []string{"report", "report.html", "out/agentic-scan", "run.tar.gz", ""} {
		specs := []exportFormatSpec{{format: "html", raw: "html"}}
		assignExportPaths(specs, base)
		if specs[0].path != base {
			t.Errorf("assignExportPaths(single, %q) path = %q, want %q verbatim", base, specs[0].path, base)
		}
	}
}

// TestAssignExportPathsMultiFormat covers the derivation that makes
// `--format html,bundle,markdown -o base` work: one path per format off the
// shared base, each with its own extension, and no two formats colliding.
func TestAssignExportPathsMultiFormat(t *testing.T) {
	tests := []struct {
		name    string
		formats string
		base    string
		want    map[string]string
	}{
		{
			name:    "bare base",
			formats: "html,bundle,markdown",
			base:    "agentic-authenticated-scan",
			want: map[string]string{
				"html":     "agentic-authenticated-scan.html",
				"bundle":   "agentic-authenticated-scan.tar.gz",
				"markdown": "agentic-authenticated-scan.md",
			},
		},
		{
			name:    "base extension is replaced, not appended to",
			formats: "html,jsonl",
			base:    "out/scan.html",
			want: map[string]string{
				"html":  "out/scan.html",
				"jsonl": "out/scan.jsonl",
			},
		},
		{
			name:    "archive base does not leak .tar into siblings",
			formats: "bundle,html",
			base:    "run.tar.gz",
			want: map[string]string{
				"bundle": "run.tar.gz",
				"html":   "run.html",
			},
		},
		{
			name:    "fs keeps the bare base as its directory stem",
			formats: "fs,html",
			base:    "out/run.html",
			want: map[string]string{
				"fs":   "out/run",
				"html": "out/run.html",
			},
		},
		{
			name:    "gs:// destinations derive per format too",
			formats: "html,markdown",
			base:    "gs://proj/reports/scan",
			want: map[string]string{
				"html":     "gs://proj/reports/scan.html",
				"markdown": "gs://proj/reports/scan.md",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specs, err := parseExportFormats(tt.formats)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assignExportPaths(specs, tt.base)

			seen := make(map[string]string, len(specs))
			for _, s := range specs {
				if want := tt.want[s.format]; s.path != want {
					t.Errorf("format %s path = %q, want %q", s.format, s.path, want)
				}
				if other, dup := seen[s.path]; dup {
					t.Errorf("formats %s and %s both resolved to %q", other, s.format, s.path)
				}
				seen[s.path] = s.format
			}
		})
	}
}

// TestValidateExportFormatPath covers the per-format output requirements, which
// are enforced against the derived path rather than the raw -o value.
func TestValidateExportFormatPath(t *testing.T) {
	tests := []struct {
		name    string
		spec    exportFormatSpec
		wantErr string
	}{
		{name: "html needs output", spec: exportFormatSpec{format: "html", raw: "html"}, wantErr: "requires -o/--output"},
		{name: "markdown needs output", spec: exportFormatSpec{format: "markdown", raw: "md"}, wantErr: "requires -o/--output"},
		{name: "pdf needs output", spec: exportFormatSpec{format: "pdf", raw: "pdf"}, wantErr: "requires -o/--output"},
		{name: "report needs output", spec: exportFormatSpec{format: "report", raw: "report"}, wantErr: "requires -o/--output"},
		{name: "jsonl streams to stdout", spec: exportFormatSpec{format: "jsonl", raw: "jsonl"}},
		{name: "fs defaults its base", spec: exportFormatSpec{format: "fs", raw: "fs"}},
		{name: "html with output", spec: exportFormatSpec{format: "html", raw: "html", path: "report.html"}},
		{
			name:    "bundle rejects a non-archive path",
			spec:    exportFormatSpec{format: "bundle", raw: "bundle", path: "report"},
			wantErr: "requires -o ending in .tar.gz or .tgz",
		},
		{name: "bundle accepts .tar.gz", spec: exportFormatSpec{format: "bundle", raw: "bundle", path: "report.tar.gz"}},
		{name: "bundle accepts .tgz", spec: exportFormatSpec{format: "bundle", raw: "gz", path: "report.tgz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExportFormatPath(tt.spec)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateExportFormatPath(%+v) unexpected error: %v", tt.spec, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateExportFormatPath(%+v) = nil, want error %q", tt.spec, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestMultiFormatBundleDerivesArchiveExtension is the case that used to be
// unreachable: bundle alongside other formats off one -o that carries no
// archive extension. The derived path must satisfy bundle's own suffix check.
func TestMultiFormatBundleDerivesArchiveExtension(t *testing.T) {
	specs, err := parseExportFormats("html,bundle,markdown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assignExportPaths(specs, "agentic-authenticated-scan")
	for _, s := range specs {
		if err := validateExportFormatPath(s); err != nil {
			t.Errorf("validateExportFormatPath(%s -> %s) = %v, want nil", s.format, s.path, err)
		}
	}
}
