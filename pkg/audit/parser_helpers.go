package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func resolveRepoName(state *State, folderPath string) string {
	if len(state.Audits) > 0 {
		audit := state.Audits[0]
		if audit.RepoURL != "" {
			return audit.RepoURL
		}
		if repo := audit.EffectiveRepo(); repo != "" {
			return repo
		}
	}

	if name := extractRepoFromCommitRecon(folderPath); name != "" {
		return name
	}

	return filepath.Base(folderPath)
}

// repoLineRegex matches "**Repository**: value" in commit-recon-report.md.
// Captures the value after the colon, which may be a slug like "Kong/kong"
// or a slug followed by a URL like "goharbor/harbor (https://github.com/goharbor/harbor)".
var repoLineRegex = regexp.MustCompile(`(?m)^\*\*Repository\*\*:\s*(.+)$`)

// repoURLInParens extracts a URL from parentheses, e.g. "(https://github.com/goharbor/harbor)".
var repoURLInParens = regexp.MustCompile(`\((https?://[^\s)]+)\)`)

func extractRepoFromCommitRecon(folderPath string) string {
	data, err := os.ReadFile(filepath.Join(folderPath, "commit-recon-report.md"))
	if err != nil {
		return ""
	}

	m := repoLineRegex.FindSubmatch(data)
	if m == nil {
		return ""
	}
	val := strings.TrimSpace(string(m[1]))

	// Prefer a URL in parentheses if present (e.g. "goharbor/harbor (https://...)")
	if urlMatch := repoURLInParens.FindStringSubmatch(val); urlMatch != nil {
		return urlMatch[1]
	}

	// Otherwise return the raw value (typically an org/repo slug)
	return val
}

// --- helpers ---

var cweRegex = regexp.MustCompile(`(CWE-\d+)`)

func extractCWE(val string) string {
	m := cweRegex.FindString(val)
	return m
}

var (
	fileLocRegex = regexp.MustCompile(`\*\*File\*\*:\s*` + "`" + `([^` + "`" + `]+)` + "`")
	codeLocRegex = regexp.MustCompile("`" + `([^` + "`" + `]+\.\w+:\d+(?:-\d+)?)` + "`" + `\s*--`)
)

func extractLocations(content string) []string {
	var locs []string
	seen := make(map[string]bool)

	for _, m := range fileLocRegex.FindAllStringSubmatch(content, -1) {
		loc := m[1]
		if !seen[loc] {
			seen[loc] = true
			locs = append(locs, loc)
		}
	}

	for _, m := range codeLocRegex.FindAllStringSubmatch(content, -1) {
		loc := m[1]
		if !seen[loc] {
			seen[loc] = true
			locs = append(locs, loc)
		}
	}

	return locs
}

func extractTitleFromBody(content, slug string) string {
	// Try to find title in ## Summary section first line
	summaryIdx := strings.Index(content, "## Summary")
	if summaryIdx != -1 {
		rest := content[summaryIdx+len("## Summary"):]
		lines := strings.Split(rest, "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" {
				// Use first non-empty line as title, truncated
				if len(l) > 200 {
					l = l[:200]
				}
				return l
			}
		}
	}
	// Fall back to humanized slug
	return strings.ReplaceAll(slug, "-", " ")
}

func mapConfidence(val string) string {
	switch strings.ToUpper(strings.TrimSpace(val)) {
	case "CONFIRMED", "HIGH", "VALID":
		return "firm"
	default:
		return "tentative"
	}
}

// sanitizeTrailingFences removes orphaned trailing code fences from markdown.
// LLM-generated content sometimes emits an extra ``` after a properly closed
// fenced code block. We detect this by walking through all fence markers: if
// the total count is odd the last fence is unmatched, so we strip it.
// maxBacktickRun returns the longest run of consecutive backticks in s, or 2
// when no backticks are present (so callers can default to a 3-backtick fence
// via maxBacktickRun(s)+1).
func maxBacktickRun(s string) int {
	max, cur := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			cur++
			if cur > max {
				max = cur
			}
		} else {
			cur = 0
		}
	}
	if max < 2 {
		return 2
	}
	return max
}

func sanitizeTrailingFences(s string) string {
	lines := strings.Split(s, "\n")

	inCodeBlock := false
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inCodeBlock = !inCodeBlock
		}
	}

	if !inCodeBlock {
		return s
	}

	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
			lines = append(lines[:i], lines[i+1:]...)
			break
		}
	}

	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	return strings.Join(lines, "\n")
}
