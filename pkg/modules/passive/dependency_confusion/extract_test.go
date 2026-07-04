package dependency_confusion

import (
	"sort"
	"testing"
)

func sortedEq(t *testing.T, got, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mismatch: got %v, want %v", got, want)
		}
	}
}

func TestNormalizePackageName(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"left-pad", "left-pad", true},
		{"@scope/name", "@scope/name", true},
		{"@scope/name/sub/path", "@scope/name", true},
		{"lodash/fp", "lodash", true},
		{"@acme/lib@^1.2.0", "@acme/lib", true},
		{"left-pad@1.0.0", "left-pad", true},
		{"./relative", "", false},
		{"../up", "", false},
		{"/absolute", "", false},
		{"https://cdn/x.js", "", false},
		{"node:fs", "", false},
		{"fs", "", false},     // node builtin, unscoped
		{"crypto", "", false}, // node builtin
		{"@", "", false},      // bare scope marker
		{"@scope", "", false}, // scope without name
		{"UPPER", "", false},  // npm names are lowercase
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := normalizePackageName(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("normalizePackageName(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestExtractScopedCandidates_OnlyScopedInternal(t *testing.T) {
	body := `
		import x from "@acme/private-ui";
		import "left-pad";
		const y = require("@acme/utils");
		const z = require("lodash");
		import("@acme/lazy/chunk");
		export { a } from "@acme/reexport";
		import rel from "./local";
		import ng from "@angular/core";     // known-public scope: skipped
		import bab from "@babel/runtime";   // known-public scope: skipped
	`
	// Only scoped, non-public names survive. Bare imports (left-pad, lodash),
	// relative imports, and known-public scopes (@angular, @babel) are dropped.
	sortedEq(t, extractScopedCandidates(body),
		[]string{"@acme/private-ui", "@acme/utils", "@acme/lazy", "@acme/reexport"})
}

func TestExtractScopedCandidates_KnownPublicScopesSkipped(t *testing.T) {
	body := `
		import a from "@types/node";
		import b from "@aws-sdk/client-s3";
		import c from "@sentry/react";
		import d from "@tanstack/react-query";
		import e from "@mui/material/Button";
	`
	if got := extractScopedCandidates(body); len(got) != 0 {
		t.Fatalf("expected all known-public scopes skipped, got %v", got)
	}
}

func TestExtractScopedCandidates_JunkNotExtracted(t *testing.T) {
	// Quoted strings that are not import/require specifiers, minified junk, and
	// invalid names must not be treated as packages.
	body := `
		const s = "@acme/not an import, just a string";
		console.log("@totally/fake");
		fetch("https://example.com/@acme/api");
		const bad = "@Bad/Uppercase";
		var chunk = "@acme/"; // no package part
	`
	if got := extractScopedCandidates(body); len(got) != 0 {
		t.Fatalf("expected no packages from non-import junk, got %v", got)
	}
}

func TestExtractScopedCandidates_ImportWordInStringLiteral(t *testing.T) {
	// A string literal containing the word "import" (or "require") must not
	// swallow the real import that follows it on the next statement.
	body := `
		const label = "@vendor/not-an-import-helper";
		var msg = "please require a token";
		import real from "@acme/real-lib";
	`
	sortedEq(t, extractScopedCandidates(body), []string{"@acme/real-lib"})
}

func TestExtractScopedCandidates_Minified(t *testing.T) {
	// Minified bundles drop whitespace: import{a as b}from"@acme/x";
	body := `import{a as b}from"@acme/min-a";export*from"@acme/min-b";const n=require("@acme/min-c");`
	sortedEq(t, extractScopedCandidates(body),
		[]string{"@acme/min-a", "@acme/min-b", "@acme/min-c"})
}

func TestExtractScopedCandidates_Dedup(t *testing.T) {
	body := `
		import a from "@acme/dup";
		const b = require("@acme/dup");
		import("@acme/dup");
	`
	sortedEq(t, extractScopedCandidates(body), []string{"@acme/dup"})
}

func TestIsKnownPublicScope(t *testing.T) {
	cases := map[string]bool{
		"@angular/core":   true,
		"@babel/runtime":  true,
		"@aws-sdk/client": true,
		"@acme/internal":  false,
		"left-pad":        false,
		"@acme":           false, // malformed, no scope separator
	}
	for name, want := range cases {
		if got := isKnownPublicScope(name); got != want {
			t.Errorf("isKnownPublicScope(%q) = %v, want %v", name, got, want)
		}
	}
}
