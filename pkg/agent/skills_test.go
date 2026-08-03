package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopySkillsToSessionDir_EmptyDir(t *testing.T) {
	// Should not panic with empty session dir
	CopySkillsToSessionDir("")
}

func TestCopySkillsToSessionDir_VigoliumScannerCopied(t *testing.T) {
	sessionDir := t.TempDir()

	CopySkillsToSessionDir(sessionDir)

	skillPath := filepath.Join(sessionDir, "skills", "vigolium-scanner", "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		t.Errorf("vigolium-scanner SKILL.md should exist, got error: %v", err)
	}

	// Verify references subdirectory is also copied
	refsDir := filepath.Join(sessionDir, "skills", "vigolium-scanner", "references")
	entries, err := os.ReadDir(refsDir)
	if err != nil {
		t.Fatalf("vigolium-scanner references dir should exist: %v", err)
	}
	if len(entries) == 0 {
		t.Error("vigolium-scanner references dir should contain files")
	}
}

func TestCopySkillsToSessionDir_Idempotent(t *testing.T) {
	sessionDir := t.TempDir()

	CopySkillsToSessionDir(sessionDir)
	CopySkillsToSessionDir(sessionDir)

	skillPath := filepath.Join(sessionDir, "skills", "vigolium-scanner", "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		t.Errorf("SKILL.md should exist after double copy: %v", err)
	}
}
