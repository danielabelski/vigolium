package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfidenceRankFor(t *testing.T) {
	cases := []struct {
		in    string
		rank  int
		known bool
	}{
		{"low", 0, true},
		{"LOW", 0, true},
		{"medium", 1, true},
		{"med", 1, true},
		{" high ", 2, true},
		{"bogus", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		rank, known := confidenceRankFor(c.in)
		if rank != c.rank || known != c.known {
			t.Errorf("confidenceRankFor(%q) = (%d,%v), want (%d,%v)", c.in, rank, known, c.rank, c.known)
		}
	}
}

func TestRedactSecret(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"abcdef", "******"},   // <= 2*keep, fully masked
		{"abcdefg", "abc*efg"}, // 7 chars: keep 3 each end, 1 star between
		{"sk_live_0123456789", "sk_************789"},
	}
	for _, c := range cases {
		if got := redactSecret(c.in); got != c.want {
			t.Errorf("redactSecret(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// A redacted secret never reveals the full middle.
	if got := redactSecret("supersecretvalue"); strings.Contains(got, "secret") {
		t.Errorf("redactSecret leaked the middle: %q", got)
	}
}

func TestLineOfOffset(t *testing.T) {
	data := []byte("line1\nline2\nline3")
	cases := []struct {
		off, line int
	}{
		{0, 1},
		{5, 1},  // the newline itself is still on line 1
		{6, 2},  // first byte of line2
		{12, 3}, // first byte of line3
		{9999, 3},
		{-5, 1},
	}
	for _, c := range cases {
		if got := lineOfOffset(data, c.off); got != c.line {
			t.Errorf("lineOfOffset(off=%d) = %d, want %d", c.off, got, c.line)
		}
	}
}

func TestToSet(t *testing.T) {
	if toSet(nil) != nil {
		t.Error("toSet(nil) should be nil")
	}
	s := toSet([]string{"a", " b ", "", "a"})
	if len(s) != 2 || !s["a"] || !s["b"] {
		t.Errorf("toSet trimming/dedup wrong: %v", s)
	}
}

func TestKitNormalizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"https://acme.test/path?x=1", "acme.test"},
		{"http://acme.test:8443/a", "acme.test"},
		{"acme.test:8443", "acme.test"},
		{"acme.test/robots.txt", "acme.test"},
		{"  spaced.test  ", "spaced.test"},
		{"# comment", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := kitNormalizeDomain(c.in); got != c.want {
			t.Errorf("kitNormalizeDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestKitCollectDomainsDedupAndNormalize(t *testing.T) {
	// Explicit args (no "-"), so stdin is never consulted.
	got, err := kitCollectDomains([]string{"https://a.test/x", "A.TEST", "b.test:80", "# c"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.test", "b.test"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadOASTSession(t *testing.T) {
	dir := t.TempDir()

	// Missing file yields a helpful, actionable error.
	if _, err := loadOASTSession(filepath.Join(dir, "nope.yaml")); err == nil {
		t.Error("expected error for missing session file")
	} else if !strings.Contains(err.Error(), "oast new") {
		t.Errorf("missing-file error should point at `oast new`, got: %v", err)
	}

	// A session missing the correlation id / private key is rejected.
	incomplete := filepath.Join(dir, "incomplete.yaml")
	if err := os.WriteFile(incomplete, []byte("server-url: https://oast.pro\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOASTSession(incomplete); err == nil {
		t.Error("expected error for a session missing correlation id / private key")
	}

	// A well-formed session round-trips.
	good := filepath.Join(dir, "good.yaml")
	content := "server-url: https://oast.pro\n" +
		"server-token: tok\n" +
		"private-key: PRIVKEYDATA\n" +
		"correlation-id: abcdef1234567890\n" +
		"secret-key: sek\n" +
		"public-key: PUBKEYDATA\n"
	if err := os.WriteFile(good, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	si, err := loadOASTSession(good)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if si.CorrelationID != "abcdef1234567890" || si.ServerURL != "https://oast.pro" || si.Token != "tok" {
		t.Errorf("session parsed wrong: %+v", si)
	}
}

func TestResolveWordlistName(t *testing.T) {
	available := []string{"dir-long.txt", "fuzz.txt", "jwt.secrets.list"}
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"fuzz.txt", "fuzz.txt", true},    // exact filename
		{"fuzz", "fuzz.txt", true},        // basename without extension
		{"FUZZ", "fuzz.txt", true},        // case-insensitive
		{"jwt", "jwt.secrets.list", true}, // friendly alias
		{"jwt.secrets", "jwt.secrets.list", true},
		{"dir-long", "dir-long.txt", true},
		{"nope", "", false},
	}
	for _, c := range cases {
		got, ok := resolveWordlistName(c.in, available)
		if ok != c.ok || got != c.want {
			t.Errorf("resolveWordlistName(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSplitWordlistEntries(t *testing.T) {
	data := []byte("a\n# comment\n\n  b  \nc\n")
	got := splitWordlistEntries(data)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestKitReadJWTStripsBearer(t *testing.T) {
	if got, _ := kitReadJWT("Bearer abc.def.ghi"); got != "abc.def.ghi" {
		t.Errorf("kitReadJWT did not strip Bearer: %q", got)
	}
	if got, _ := kitReadJWT("  abc.def.ghi  "); got != "abc.def.ghi" {
		t.Errorf("kitReadJWT did not trim: %q", got)
	}
}

func TestKitResolveJSInputFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.js")
	if err := os.WriteFile(p, []byte("var x=1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, label, mt, err := kitResolveJSInput(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "var x=1;" || label != p || mt != "application/javascript" {
		t.Errorf("file input resolved wrong: data=%q label=%q mt=%q", data, label, mt)
	}
}
