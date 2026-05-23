package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func parseFindingsDir(dir string) ([]*Finding, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil // no findings-draft directory is valid (empty audit)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	// First pass: parse base findings (skip .cold-verify.md files)
	findingsByID := make(map[string]*Finding)
	var findings []*Finding

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		if strings.Contains(e.Name(), ".cold-verify.") {
			continue // handle in second pass
		}

		path := filepath.Join(dir, e.Name())
		af, err := parseFindingFile(path)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		if af != nil {
			findingsByID[af.FindingID] = af
			findings = append(findings, af)
		}
	}

	// Second pass: apply cold-verify overlays
	for _, e := range entries {
		if !strings.Contains(e.Name(), ".cold-verify.md") {
			continue
		}

		path := filepath.Join(dir, e.Name())
		overlay, err := parseFindingFile(path)
		if err != nil {
			continue // skip unparseable cold-verify files
		}
		if overlay == nil {
			continue
		}

		// Find the base finding to overlay
		if base, ok := findingsByID[overlay.FindingID]; ok {
			applyColdVerify(base, overlay)
		}
	}

	return findings, nil
}

// findingFileRegex matches audit finding filenames like p7-001-slug.md or p8-002-slug.cold-verify.md
var findingFileRegex = regexp.MustCompile(`^p(\d+)-(\d+)-(.+?)(?:\.cold-verify)?\.md$`)

// liteFindingFileRegex matches legacy lite-mode filenames like l1-001.md or l2-003.md (no slug).
var liteFindingFileRegex = regexp.MustCompile(`^l(\d+)-(\d+)\.md$`)

// quickFindingFileRegex matches current lite-mode filenames like q1-001.md or q2-009.md.
// Lite mode phases are Q0 (recon), Q1 (secrets scan), Q2 (fast SAST); only Q1/Q2 emit findings.
var quickFindingFileRegex = regexp.MustCompile(`^q(\d+)-(\d+)\.md$`)

// promotedFindingRegex matches severity-prefixed promoted finding names.
// Matches both directory entries (C1-sqli-user-lookup) and flat files (C1.md, H2-weak-jwt.md).
// Group 1: severity letter (C/H/M/L), Group 2: sequence, Group 3: optional slug.
var promotedFindingRegex = regexp.MustCompile(`^([CHML])(\d+)(?:-(.+?))?$`)

// phasePrefixedDirRegex matches piolium's promoted-finding directory naming,
// which keeps the source phase-prefixed ID rather than promoting to severity-
// letter format. Examples: "p10-001-direct-git-url-ref-reaches-…",
// "p12-cleartext-http-git-sources" (no sequence — slug only).
// Group 1: phase digits, Group 2: optional sequence digits, Group 3: optional slug.
var phasePrefixedDirRegex = regexp.MustCompile(`^p(\d+)(?:-(\d+))?(?:-(.+?))?$`)

func parseFindingFile(path string) (*Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	filename := filepath.Base(path)
	content := string(data)

	// Try standard deep/scan-mode pattern first: p<phase>-<seq>-<slug>.md
	if m := findingFileRegex.FindStringSubmatch(filename); m != nil {
		phase := m[1]
		seq := m[2]
		slug := m[3]
		findingID := fmt.Sprintf("P%s-%s", phase, seq)

		af := &Finding{
			FindingID: findingID,
			Phase:     phase,
			Sequence:  seq,
			Slug:      slug,
			Filename:  filename,
		}

		if phase == "7" {
			parsePhase7Finding(af, content)
		} else {
			parseFrontmatterFinding(af, content)
		}
		return af, nil
	}

	// Try legacy lite-mode pattern: l<phase>-<seq>.md
	if m := liteFindingFileRegex.FindStringSubmatch(filename); m != nil {
		phase := m[1]
		seq := m[2]
		findingID := fmt.Sprintf("L%s-%s", phase, seq)

		af := &Finding{
			FindingID: findingID,
			Phase:     phase,
			Sequence:  seq,
			Filename:  filename,
		}
		parseLiteFinding(af, content)
		return af, nil
	}

	// Try current lite-mode pattern: q<phase>-<seq>.md
	if m := quickFindingFileRegex.FindStringSubmatch(filename); m != nil {
		phase := m[1]
		seq := m[2]
		findingID := fmt.Sprintf("Q%s-%s", phase, seq)

		af := &Finding{
			FindingID: findingID,
			Phase:     phase,
			Sequence:  seq,
			Filename:  filename,
		}
		parseLiteFinding(af, content)
		return af, nil
	}

	return nil, nil // not a finding file
}

// parsePromotedFindings reads the audit/findings/ directory where confirmed
// findings have been promoted out of findings-draft/ with severity-prefixed IDs
// (C1, H2, M3, ...). Two layouts are supported:
//
//   - Directory per finding: findings/C1-sqli-user-lookup/{draft.md, report.md, poc.*, evidence/}
//   - Flat files: findings/C1.md + findings/C1-poc.md (test-fixture shape)
//
// Returns nil without error when the directory does not exist.
func parsePromotedFindings(dir string) ([]*Finding, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var findings []*Finding
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			// Severity-prefixed (audit: C1-sqli-user-lookup/) — try first.
			if af := parsePromotedFindingDir(filepath.Join(dir, name), name); af != nil {
				findings = append(findings, af)
				continue
			}
			// Phase-prefixed (piolium: p10-001-direct-git-url-…/). Piolium
			// keeps the source phase ID on its promoted findings rather than
			// renumbering to severity-letter format.
			if af := parsePhasePrefixedFindingDir(filepath.Join(dir, name), name); af != nil {
				findings = append(findings, af)
			}
			continue
		}
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		// Skip PoC companion files — they share an ID with the primary finding.
		base := strings.TrimSuffix(name, ".md")
		if strings.HasSuffix(base, "-poc") {
			continue
		}
		if af := parsePromotedFindingFile(filepath.Join(dir, name), base); af != nil {
			findings = append(findings, af)
		}
	}

	// Sort for deterministic ordering: severity C > H > M > L, then numeric sequence.
	sort.SliceStable(findings, func(i, j int) bool {
		return promotedSortKey(findings[i]) < promotedSortKey(findings[j])
	})
	return findings, nil
}

// promotedSortKey builds a string sort key that orders C* < H* < M* < L* and
// then pads the sequence number so C2 < C10.
func promotedSortKey(af *Finding) string {
	rank := "9"
	if len(af.FindingID) > 0 {
		switch af.FindingID[0] {
		case 'C':
			rank = "0"
		case 'H':
			rank = "1"
		case 'M':
			rank = "2"
		case 'L':
			rank = "3"
		}
	}
	return rank + fmt.Sprintf("%06s", af.Sequence) + af.FindingID
}

// readFindingDirContents populates af in place from a findings/<ID>/
// directory: parses draft.md frontmatter first, then prefers report.md
// for the body, and finally enriches with poc.* and metadata.json.
// Returns false when neither draft.md nor report.md exists. Callers must
// pre-populate af with the directory-derived identity (FindingID, Phase,
// Sequence, Slug, Severity); frontmatter from draft.md may refine it.
func readFindingDirContents(dirPath, entryName string, af *Finding) bool {
	reportData, reportErr := os.ReadFile(filepath.Join(dirPath, "report.md"))
	draftData, draftErr := os.ReadFile(filepath.Join(dirPath, "draft.md"))
	if reportErr != nil && draftErr != nil {
		return false
	}

	if draftErr == nil {
		af.Filename = entryName + "/draft.md"
		parseFrontmatterFinding(af, string(draftData))
	}
	if reportErr == nil && len(reportData) > 0 {
		af.Filename = entryName + "/report.md"
		reportContent := string(reportData)
		parseReportMd(af, reportContent)
		af.Body = reportContent
	} else if draftErr == nil {
		parseLiteFinding(af, string(draftData))
	}

	if pocFile := detectPoCFile(dirPath); pocFile != "" {
		af.PoCFile = pocFile
		if pocContent, err := os.ReadFile(filepath.Join(dirPath, pocFile)); err == nil && len(pocContent) > 0 {
			const maxPoCSize = 512 * 1024
			if len(pocContent) > maxPoCSize {
				pocContent = append(pocContent[:maxPoCSize], "\n... (truncated)"...)
			}
			af.PoCContent = string(pocContent)
		}
	}
	parseMetadataJSON(af, dirPath)
	return true
}

// parsePhasePrefixedFindingDir parses a piolium-style findings/p<phase>-<seq>-<slug>/
// directory. Same content layout as the severity-prefixed audit variant;
// only the identity (FindingID, Phase, Sequence, Slug) is derived from
// the phase-prefixed directory name. Draft frontmatter may override.
func parsePhasePrefixedFindingDir(dirPath, entryName string) *Finding {
	m := phasePrefixedDirRegex.FindStringSubmatch(entryName)
	if m == nil {
		return nil
	}
	phase := m[1]
	seq := ""
	slug := ""
	if len(m) > 2 {
		seq = m[2]
	}
	if len(m) > 3 {
		slug = m[3]
	}
	findingID := "P" + phase
	if seq != "" {
		findingID = fmt.Sprintf("P%s-%s", phase, seq)
	}
	af := &Finding{FindingID: findingID, Phase: phase, Sequence: seq, Slug: slug}
	if !readFindingDirContents(dirPath, entryName, af) {
		return nil
	}
	if af.Slug == "" && slug != "" {
		af.Slug = slug
	}
	return af
}

// parsePromotedFindingDir parses a findings/<ID>-<slug>/ directory.
// Priority: report.md (polished, structured) → draft.md (frontmatter metadata).
// Also reads poc.* files and metadata.json for enrichment.
func parsePromotedFindingDir(dirPath, entryName string) *Finding {
	m := promotedFindingRegex.FindStringSubmatch(entryName)
	if m == nil {
		return nil
	}
	af := newPromotedFinding(m, entryName)
	if !readFindingDirContents(dirPath, entryName, af) {
		return nil
	}
	restorePromotedIdentity(af, m)
	return af
}

// parsePromotedFindingFile parses a flat findings/<ID>[-<slug>].md file.
func parsePromotedFindingFile(path, base string) *Finding {
	m := promotedFindingRegex.FindStringSubmatch(base)
	if m == nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	af := newPromotedFinding(m, base)
	af.Filename = base + ".md"
	parseLiteFinding(af, string(data))
	restorePromotedIdentity(af, m)
	return af
}

// newPromotedFinding creates an Finding seeded with the promoted
// ID/slug/severity from a regex match against the dir or file name.
func newPromotedFinding(m []string, entryName string) *Finding {
	sevLetter := m[1]
	seq := m[2]
	slug := ""
	if len(m) > 3 {
		slug = m[3]
	}
	return &Finding{
		FindingID: sevLetter + seq,
		Phase:     "lite",
		Sequence:  seq,
		Slug:      slug,
		Severity:  severityFromLetter(sevLetter),
	}
}

// restorePromotedIdentity re-asserts the directory/file-derived FindingID,
// slug, and severity after parseLiteFinding has run, since the lite-finding
// content parser may overwrite them from inline "## Q1-001:" style headers.
func restorePromotedIdentity(af *Finding, m []string) {
	sevLetter := m[1]
	seq := m[2]
	slug := ""
	if len(m) > 3 {
		slug = m[3]
	}

	af.FindingID = sevLetter + seq
	af.Sequence = seq
	af.Phase = "lite"
	if slug != "" {
		af.Slug = slug
	}
	// The promoted directory prefix (C/H/M/L) is the canonical severity for
	// the finding — that's the tier the auditor assigned at promotion time
	// and the one operators see when listing the findings/ tree. Any later
	// downgrade recorded inside report.md or in the draft's body (## Cold
	// Verification) is preserved as descriptive content, but does not
	// overwrite the headline severity. SeverityOriginal/SeverityFinal stay
	// available on the struct for callers that want the verdict trail.
	af.Severity = severityFromLetter(sevLetter)
}
