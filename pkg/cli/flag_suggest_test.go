package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// parseErr runs the command's flag parser over args and returns whatever
// FlagErrorFunc produced, mirroring the real cobra execute() path.
func parseErr(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()
	err := cmd.ParseFlags(args)
	if err == nil {
		return nil
	}
	return cmd.FlagErrorFunc()(cmd, err)
}

func TestFlagErrorFuncSuggestsClosestFlag(t *testing.T) {
	newCmd := func() *cobra.Command {
		c := &cobra.Command{Use: "scan-url"}
		c.SetFlagErrorFunc(flagErrorFunc)
		c.Flags().StringSlice("modules", nil, "")
		c.Flags().Bool("verbose", false, "")
		c.Flags().Bool("stateless", false, "")
		hidden := "secret"
		c.Flags().String(hidden, "", "")
		_ = c.Flags().MarkHidden(hidden)
		return c
	}

	cases := []struct {
		name       string
		args       []string
		wantSuggst string // substring the hint must contain, "" = no hint
	}{
		{"long typo", []string{"--module", "xss"}, "Did you mean --modules?"},
		{"inherited-style flag typo", []string{"--verbos"}, "Did you mean --verbose?"},
		{"no close match", []string{"--xyzzy", "1"}, ""},
		{"exact flag ok", []string{"--verbose"}, ""},
		{"never suggests a hidden flag", []string{"--secre"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := parseErr(t, newCmd(), tc.args...)
			if tc.name == "exact flag ok" {
				if err != nil {
					t.Fatalf("valid flag returned error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected a flag error for %v", tc.args)
			}
			msg := err.Error()
			if tc.wantSuggst == "" {
				if strings.Contains(msg, "Did you mean") {
					t.Fatalf("expected no suggestion, got: %q", msg)
				}
				return
			}
			if !strings.Contains(msg, tc.wantSuggst) {
				t.Fatalf("expected suggestion %q in error, got: %q", tc.wantSuggst, msg)
			}
		})
	}
}

// A mistyped shorthand must not crash and must not fabricate a long-flag
// suggestion — it carries a shortname group, not a long name.
func TestFlagErrorFuncIgnoresShorthand(t *testing.T) {
	c := &cobra.Command{Use: "scan-url"}
	c.SetFlagErrorFunc(flagErrorFunc)
	c.Flags().StringSliceP("modules", "m", nil, "")

	err := parseErr(t, c, "-Q")
	if err == nil {
		t.Fatal("expected an unknown-shorthand error")
	}
	if strings.Contains(err.Error(), "Did you mean") {
		t.Fatalf("shorthand error should not carry a long-flag suggestion: %q", err.Error())
	}
	// Sanity: it really was the shorthand error type.
	var notExist *pflag.NotExistError
	if !errors.As(err, &notExist) {
		t.Fatalf("expected a pflag.NotExistError, got %T", err)
	}
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"module", "module", 0},
		{"module", "modules", 1},
		{"modul", "modules", 2},
		{"", "abc", 3},
		{"abc", "", 3},
		{"kitten", "sitting", 3},
	}
	for _, tc := range cases {
		if got := levenshtein(tc.a, tc.b); got != tc.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
