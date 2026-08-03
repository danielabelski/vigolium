package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBundledSkills(t *testing.T) {
	skills, err := loadBundledSkills()
	if err != nil {
		t.Fatalf("loadBundledSkills: %v", err)
	}
	if len(skills) == 0 {
		t.Fatal("expected at least one bundled skill")
	}

	// The flagship scanner skill must always be present with metadata.
	vs, ok := findBundle(skills, defaultInstallSkill)
	if !ok {
		t.Fatalf("bundled skills missing %q: got %s", defaultInstallSkill, bundleNames(skills))
	}
	if len(vs.References) == 0 {
		t.Error("vigolium-scanner should expose reference files")
	}

	// Descriptions come from skill.Parse, which is strict — an empty one
	// means the bundle's frontmatter is malformed and it would list blank.
	for _, s := range skills {
		if s.Description == "" {
			t.Errorf("bundle %q has no description (malformed frontmatter?)", s.Name)
		}
	}
}

func TestSkillsInstallBaseDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cwd: %v", err)
	}

	tests := []struct {
		agent, scope string
		want         string
	}{
		{"claude", "project", filepath.Join(cwd, ".claude", "skills")},
		{"claude", "global", filepath.Join(home, ".claude", "skills")},
		{"codex", "project", filepath.Join(cwd, ".agents", "skills")},
		{"codex", "global", filepath.Join(home, ".agents", "skills")},
		{"agents", "project", filepath.Join(cwd, ".agents", "skills")},
		{"AGENTS", "GLOBAL", filepath.Join(home, ".agents", "skills")}, // case-insensitive
	}
	for _, tt := range tests {
		got, err := skillsInstallBaseDir(tt.agent, tt.scope)
		if err != nil {
			t.Errorf("skillsInstallBaseDir(%q,%q): %v", tt.agent, tt.scope, err)
			continue
		}
		if got != tt.want {
			t.Errorf("skillsInstallBaseDir(%q,%q) = %q, want %q", tt.agent, tt.scope, got, tt.want)
		}
	}

	if _, err := skillsInstallBaseDir("nope", "project"); err == nil {
		t.Error("expected error for unknown agent")
	}
	if _, err := skillsInstallBaseDir("claude", "nope"); err == nil {
		t.Error("expected error for unknown scope")
	}
}

func TestCopyEmbeddedSkillBundle(t *testing.T) {
	skills, err := loadBundledSkills()
	if err != nil {
		t.Fatalf("loadBundledSkills: %v", err)
	}
	vs, ok := findBundle(skills, defaultInstallSkill)
	if !ok {
		t.Fatalf("missing %q", defaultInstallSkill)
	}

	dest := filepath.Join(t.TempDir(), vs.Name)
	if err := copyEmbeddedSkillBundle(vs.EmbedDir, dest); err != nil {
		t.Fatalf("copyEmbeddedSkillBundle: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "SKILL.md")); err != nil {
		t.Errorf("SKILL.md not copied: %v", err)
	}
	for _, ref := range vs.References {
		if _, err := os.Stat(filepath.Join(dest, ref)); err != nil {
			t.Errorf("reference %s not copied: %v", ref, err)
		}
	}
}

func TestFindBundleCaseInsensitive(t *testing.T) {
	skills := []bundledSkill{{Name: "vigolium-scanner"}, {Name: "other-skill"}}
	if _, ok := findBundle(skills, "VIGOLIUM-SCANNER"); !ok {
		t.Error("findBundle should be case-insensitive")
	}
	if _, ok := findBundle(skills, "missing"); ok {
		t.Error("findBundle should not match a missing name")
	}
	if got := bundleNames(skills); !strings.Contains(got, "vigolium-scanner") || !strings.Contains(got, "other-skill") {
		t.Errorf("bundleNames = %q", got)
	}
}
