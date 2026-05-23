package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// mdParser is a reusable goldmark markdown parser.
var mdParser = goldmark.DefaultParser()

// reportTitleSepRegex strips the finding-ID prefix from H1 headings:
// "H3 — Title" or "M9 - Title" → "Title".
var reportTitleSepRegex = regexp.MustCompile(`^\S+\s*(?:—|--|-)\s*`)

// reportBoldKVRegex matches **Key**: Value patterns within paragraph text.
var reportBoldKVRegex = regexp.MustCompile(`\*\*(.+?)\*\*:\s*(.+)`)

// reportPlainKVRegex matches plain Key: Value lines.
var reportPlainKVRegex = regexp.MustCompile(`^([A-Za-z][A-Za-z _-]+?):\s*(.+)$`)

// parseReportMd uses goldmark AST to extract structured fields from report.md.
// Handles all observed LLM format variants (bold-header, plain-kv, H1-title).
func parseReportMd(af *Finding, content string) {
	source := []byte(content)
	reader := text.NewReader(source)
	doc := mdParser.Parse(reader)

	sections := parseMdSections(doc, source)

	// Extract title from H1 heading.
	if h1 := sections.h1Text; h1 != "" {
		title := reportTitleSepRegex.ReplaceAllString(h1, "")
		if title != "" {
			af.Title = strings.TrimSpace(title)
		}
	}

	// Extract metadata from the preamble (content before first ## heading).
	for _, line := range sections.preambleLines {
		// Bold key-value: **Severity**: HIGH
		if m := reportBoldKVRegex.FindStringSubmatch(line); m != nil {
			applyReportField(af, strings.TrimSpace(m[1]), strings.TrimSpace(m[2]))
			continue
		}
		// Plain key-value: Severity: HIGH
		if m := reportPlainKVRegex.FindStringSubmatch(line); m != nil {
			applyReportField(af, strings.TrimSpace(m[1]), strings.TrimSpace(m[2]))
		}
	}

	// If no title from H1, try a Title field or first Summary paragraph.
	if af.Title == "" {
		af.Title = extractTitleFromBody(content, af.Slug)
	}

	// Extract locations from the full body (regex-based, works across all formats).
	if locs := extractLocations(content); len(locs) > 0 {
		af.Locations = locs
	}

	// Extract remediation from ## Fix / ## Remediation / ## Recommendation.
	for _, name := range []string{"Fix", "Remediation", "Recommendation"} {
		if body := sections.sectionBody(name); body != "" {
			af.Remediation = body
			break
		}
	}
}

// mdSections holds the parsed structure of a markdown document.
type mdSections struct {
	h1Text        string
	preambleLines []string          // text lines before the first ## heading
	sections      map[string]string // lowercase heading → raw text body
}

// sectionBody returns the body of a named section (case-insensitive).
func (s *mdSections) sectionBody(name string) string {
	return s.sections[strings.ToLower(name)]
}

// parseMdSections walks the goldmark AST to extract the document structure.
func parseMdSections(doc ast.Node, source []byte) *mdSections {
	result := &mdSections{
		sections: make(map[string]string),
	}

	var currentHeading string
	var currentLevel int
	var sectionStart int
	firstH2Offset := -1

	for node := doc.FirstChild(); node != nil; node = node.NextSibling() {
		if heading, ok := node.(*ast.Heading); ok {
			// Flush previous section.
			if currentHeading != "" && sectionStart > 0 {
				body := extractNodeRangeText(source, sectionStart, nodeStartOffset(node))
				result.sections[strings.ToLower(currentHeading)] = strings.TrimSpace(body)
			}

			headingText := nodeInlineText(heading, source)

			if heading.Level == 1 && result.h1Text == "" {
				result.h1Text = headingText
				currentHeading = ""
				currentLevel = 0
				sectionStart = 0
				continue
			}

			if heading.Level == 2 {
				if firstH2Offset == -1 {
					firstH2Offset = nodeStartOffset(node)
					// Collect preamble lines (between H1 and first H2).
					preambleEnd := firstH2Offset
					result.preambleLines = splitPreambleLines(source, result.h1Text, preambleEnd)
				}
				currentHeading = headingText
				currentLevel = heading.Level
				sectionStart = nodeEndOffset(node, source)
			} else if heading.Level > 2 && currentLevel >= 2 {
				// Sub-headings within a section — keep accumulating.
				continue
			}
		}
	}

	// Flush final section.
	if currentHeading != "" && sectionStart > 0 {
		body := string(source[sectionStart:])
		result.sections[strings.ToLower(currentHeading)] = strings.TrimSpace(body)
	}

	// If no H2 was found, treat everything as preamble.
	if firstH2Offset == -1 {
		result.preambleLines = splitPreambleLines(source, result.h1Text, len(source))
	}

	return result
}

// nodeInlineText extracts the plain text content of a heading node.
func nodeInlineText(n ast.Node, source []byte) string {
	var buf strings.Builder
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if t, ok := c.(*ast.Text); ok {
			buf.Write(t.Segment.Value(source))
		} else {
			// Recurse into inline elements (bold, code, etc.)
			buf.WriteString(nodeInlineText(c, source))
		}
	}
	return buf.String()
}

// nodeStartOffset returns the byte offset where a node starts in the source.
func nodeStartOffset(n ast.Node) int {
	if n.HasChildren() {
		first := n.FirstChild()
		if first != nil && first.Type() == ast.TypeInline {
			if t, ok := first.(*ast.Text); ok {
				return t.Segment.Start
			}
		}
	}
	if lines := n.Lines(); lines != nil && lines.Len() > 0 {
		return lines.At(0).Start
	}
	return 0
}

// nodeEndOffset returns the byte offset after the last line of a node.
func nodeEndOffset(n ast.Node, source []byte) int {
	if lines := n.Lines(); lines != nil && lines.Len() > 0 {
		return lines.At(lines.Len() - 1).Stop
	}
	// For headings without body lines, find the next newline after the heading text.
	start := nodeStartOffset(n)
	idx := bytes.IndexByte(source[start:], '\n')
	if idx >= 0 {
		return start + idx + 1
	}
	return start
}

// extractNodeRangeText extracts text between two byte offsets.
func extractNodeRangeText(source []byte, start, end int) string {
	if start >= end || start >= len(source) {
		return ""
	}
	if end > len(source) {
		end = len(source)
	}
	return string(source[start:end])
}

// splitPreambleLines extracts non-empty text lines from the preamble area.
func splitPreambleLines(source []byte, h1Text string, endOffset int) []string {
	if endOffset > len(source) {
		endOffset = len(source)
	}
	raw := string(source[:endOffset])

	// Skip past the H1 heading line if present.
	if h1Text != "" {
		if idx := strings.Index(raw, h1Text); idx >= 0 {
			nlIdx := strings.IndexByte(raw[idx:], '\n')
			if nlIdx >= 0 {
				raw = raw[idx+nlIdx+1:]
			}
		}
	}

	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed != "---" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// applyReportField maps a key-value pair from report.md header to Finding fields.
func applyReportField(af *Finding, key, val string) {
	switch strings.ToLower(key) {
	case "severity":
		if af.Severity == "" || af.SeverityFinal == "" {
			af.Severity = val
		}
	case "poc-status":
		af.PoCStatus = val
	case "status":
		if strings.Contains(strings.ToLower(val), "confirmed") {
			af.Verdict = "VALID"
		}
		if strings.Contains(strings.ToLower(val), "poc executed") {
			af.PoCStatus = "executed"
		}
	case "title":
		if af.Title == "" {
			af.Title = val
		}
	case "cwe", "cwe context":
		if cwe := extractCWE(val); cwe != "" {
			af.CWE = cwe
		}
	case "cve context":
		if cwe := extractCWE(val); cwe != "" && af.CWE == "" {
			af.CWE = cwe
		}
	case "component":
		val = strings.Trim(val, "`")
		if len(af.Locations) == 0 {
			af.Locations = append(af.Locations, val)
		}
	case "confidence":
		af.Confidence = val
	}
}

// detectPoCFile returns the filename of a poc.* file in the directory, or empty string.
func detectPoCFile(dirPath string) string {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "poc.") {
			return name
		}
	}
	return ""
}

// findingMetadata is the JSON structure of metadata.json in a promoted finding dir.
type findingMetadata struct {
	IsVariant       bool   `json:"is_variant"`
	OriginFindingID string `json:"origin_finding_id"`
	OriginPattern   string `json:"origin_pattern"`
	Round           int    `json:"round,omitempty"`
	RevisitID       string `json:"revisit_id,omitempty"`
	Model           string `json:"model,omitempty"`
	AgentSDK        string `json:"agent_sdk,omitempty"`
}

// parseMetadataJSON reads metadata.json and populates variant fields on the finding.
func parseMetadataJSON(af *Finding, dirPath string) {
	data, err := os.ReadFile(filepath.Join(dirPath, "metadata.json"))
	if err != nil {
		return
	}
	var meta findingMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return
	}
	af.IsVariant = meta.IsVariant
	if meta.OriginFindingID != "" {
		af.OriginFindingID = meta.OriginFindingID
	}
}

// severityFromLetter maps the C/H/M/L prefix of a promoted finding ID to a
// severity word that toDBFinding will normalize.
func severityFromLetter(letter string) string {
	switch letter {
	case "C":
		return "Critical"
	case "H":
		return "High"
	case "M":
		return "Medium"
	case "L":
		return "Low"
	}
	return ""
}

// parsePhase7Finding parses the Phase 7 table-header format.
func parsePhase7Finding(af *Finding, content string) {
	// Extract fields from markdown table rows: | **Field** | Value |
	tableFieldRe := regexp.MustCompile(`\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|`)
	for _, match := range tableFieldRe.FindAllStringSubmatch(content, -1) {
		key := strings.TrimSpace(match[1])
		val := strings.TrimSpace(match[2])
		switch key {
		case "Title":
			af.Title = val
		case "Severity":
			af.Severity = val
		case "Confidence":
			af.Confidence = val
		case "CWE":
			af.CWE = extractCWE(val)
		}
	}

	// Extract PoC-Status from inline text
	if idx := strings.Index(content, "PoC-Status:"); idx != -1 {
		line := content[idx:]
		if nl := strings.IndexByte(line, '\n'); nl != -1 {
			line = line[:nl]
		}
		af.PoCStatus = strings.TrimSpace(strings.TrimPrefix(line, "PoC-Status:"))
	}

	// Extract locations from ## Code Location or ## Code Locations sections
	af.Locations = extractLocations(content)

	// Full body as description
	af.Body = content
}

// parseFrontmatterFinding parses the Phase 8/9/10 YAML-like frontmatter format.
func parseFrontmatterFinding(af *Finding, content string) {
	lines := strings.Split(content, "\n")
	bodyStart := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			// Check if next non-empty line starts a markdown section
			for j := i + 1; j < len(lines); j++ {
				next := strings.TrimSpace(lines[j])
				if next == "" {
					continue
				}
				if strings.HasPrefix(next, "## ") || strings.HasPrefix(next, "# ") {
					bodyStart = j
				}
				break
			}
			if bodyStart > 0 {
				break
			}
			continue
		}

		// Parse Key: Value lines
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx == -1 {
			continue
		}
		key := strings.TrimSpace(trimmed[:colonIdx])
		val := strings.TrimSpace(trimmed[colonIdx+1:])

		// Match keys case-insensitively. Audit uses Title-Case
		// ("Phase", "Severity-Original"); piolium uses lowercase YAML-style
		// ("phase", "severity"). The parser accepts both.
		switch strings.ToLower(key) {
		case "phase":
			af.Phase = val
		case "sequence":
			af.Sequence = val
		case "slug":
			af.Slug = val
		case "verdict":
			af.Verdict = val
		case "severity-original":
			af.SeverityOriginal = val
		case "severity-final":
			af.SeverityFinal = val
		case "severity":
			// Piolium frontmatter has a single "severity" field. Map it to
			// SeverityFinal so the existing "prefer final over original"
			// resolution still works.
			af.SeverityFinal = val
		case "poc-status":
			af.PoCStatus = val
		case "adversarial-verdict":
			af.AdversarialVerdict = val
		case "adversarial-rationale":
			af.AdversarialRationale = val
		}
	}

	// Overlay any "## Cold Verification" body block onto fields the
	// frontmatter left empty. Frontmatter remains authoritative; this only
	// fills gaps so drafts that were downgraded during cold review but
	// never promoted to a polished report.md still import with the
	// post-review verdict.
	applyColdVerificationOverlay(af, lines)

	// Extract title from ## Summary section's first sentence, or use slug
	if af.Title == "" {
		af.Title = extractTitleFromBody(content, af.Slug)
	}

	// Extract severity: prefer Severity-Final, fall back to Severity-Original
	if af.SeverityFinal != "" {
		af.Severity = af.SeverityFinal
	} else if af.SeverityOriginal != "" {
		af.Severity = af.SeverityOriginal
	}

	// Extract confidence from verdict/adversarial verdict
	if af.Confidence == "" {
		v := af.AdversarialVerdict
		if v == "" {
			v = af.Verdict
		}
		af.Confidence = mapConfidence(v)
	}

	// Extract locations
	af.Locations = extractLocations(content)

	// Full body
	if bodyStart > 0 {
		af.Body = strings.Join(lines[bodyStart:], "\n")
	} else {
		af.Body = content
	}
}

// applyColdVerificationOverlay scans content for a "## Cold Verification"
// section (written by audit's adversarial-review pass) and pulls
// Adversarial-Verdict, Adversarial-Rationale, and PoC-Status into
// Finding fields the frontmatter left empty. Frontmatter remains
// authoritative — this only fills gaps. Severity is intentionally not
// overlaid here: the directory prefix (C/H/M/L) is the canonical severity
// for promoted findings and is reasserted by restorePromotedIdentity.
func applyColdVerificationOverlay(af *Finding, lines []string) {
	headingIdx := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "## ") {
			continue
		}
		title := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed, "##")))
		if strings.HasPrefix(title, "cold verification") {
			headingIdx = i
			break
		}
	}
	if headingIdx == -1 {
		return
	}

	for j := headingIdx + 1; j < len(lines); j++ {
		trimmed := strings.TrimSpace(lines[j])
		// Stop at the next heading at any level — Cold Verification key:value
		// pairs always sit directly under the section heading; sub-sections
		// like "### Verification Details" hold prose, not structured fields.
		if strings.HasPrefix(trimmed, "#") {
			break
		}
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:colonIdx]))
		val := strings.TrimSpace(trimmed[colonIdx+1:])
		if val == "" {
			continue
		}
		switch key {
		case "adversarial-verdict":
			if af.AdversarialVerdict == "" {
				af.AdversarialVerdict = val
			}
		case "adversarial-rationale":
			if af.AdversarialRationale == "" {
				af.AdversarialRationale = val
			}
		case "poc-status":
			if af.PoCStatus == "" {
				af.PoCStatus = val
			}
		}
	}
}

// liteBoldFieldRegex matches markdown bold list items: - **Key**: Value
var liteBoldFieldRegex = regexp.MustCompile(`-\s*\*\*(.+?)\*\*:\s*(.+)`)

// liteHeadingRegex matches lite finding headings: "## l2-001: Title" or
// the current "## Q1-001: Title" (case-insensitive on the L/Q prefix).
var liteHeadingRegex = regexp.MustCompile(`(?mi)^##\s+[lq]\d+-\d+:\s*(.+)`)

// parseLiteFinding parses the lite-mode markdown format with bold list items.
func parseLiteFinding(af *Finding, content string) {
	// Extract title from ## heading
	if m := liteHeadingRegex.FindStringSubmatch(content); m != nil {
		af.Title = strings.TrimSpace(m[1])
	}

	// Extract fields from - **Key**: Value lines
	for _, m := range liteBoldFieldRegex.FindAllStringSubmatch(content, -1) {
		key := strings.TrimSpace(m[1])
		val := strings.TrimSpace(m[2])
		switch key {
		case "Severity":
			af.Severity = val
		case "File":
			af.Locations = append(af.Locations, val)
		case "Line":
			// Append line number to the last location if present
			if len(af.Locations) > 0 {
				af.Locations[len(af.Locations)-1] += ":" + val
			}
		case "Category":
			af.Slug = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(val, " ", "-"), "—", "-"))
		case "CWE":
			af.CWE = extractCWE(val)
		case "Verdict":
			af.Verdict = val
		}
	}

	// If no slug was derived from Category, create one from the title
	if af.Slug == "" && af.Title != "" {
		af.Slug = strings.ToLower(strings.ReplaceAll(af.Title, " ", "-"))
	}

	// Set confidence from verdict — store the raw verdict value so that
	// toDBFinding's mapConfidence call produces the correct result.
	if af.Confidence == "" && af.Verdict != "" {
		af.Confidence = af.Verdict
	}

	af.Body = content
}

func applyColdVerify(base, overlay *Finding) {
	if overlay.AdversarialVerdict != "" {
		base.AdversarialVerdict = overlay.AdversarialVerdict
	}
	if overlay.SeverityFinal != "" {
		base.SeverityFinal = overlay.SeverityFinal
		base.Severity = overlay.SeverityFinal
	}
	if overlay.PoCStatus != "" {
		base.PoCStatus = overlay.PoCStatus
	}
	if overlay.AdversarialRationale != "" {
		base.AdversarialRationale = overlay.AdversarialRationale
	}
	// Merge body: append cold-verify notes
	if overlay.Body != "" {
		base.Body = base.Body + "\n\n---\n## Cold Verification\n\n" + overlay.Body
	}
}
