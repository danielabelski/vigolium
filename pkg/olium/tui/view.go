package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2/quick"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// View renders the live area: a constant-size status line (so the live region
// never shrinks — shrinkage was leaving leftover ANSI cells under the input),
// the input box, and a hint line. Completed prose lines and closed fences are
// pushed into scrollback by `tea.Printf` as they stream in (see
// handleTextDelta), so the user sees the reply unfold persistently above the
// live region.
//
// Bubble Tea v2 requires View() to return a tea.View struct. We also opt in
// to kitty keyboard event reporting here so the terminal will distinguish
// shift+enter from plain enter (when supported — gracefully degrades to
// "enter" on terminals that don't negotiate the protocol).
func (m Model) View() tea.View {
	var b strings.Builder

	// Status line — always one line so the live view height only varies
	// with the textarea, not with streaming output. The streamed reply itself
	// flushes line-by-line into scrollback (see handleTextDelta); the ticker
	// here just shows the in-progress partial line that hasn't been newlined
	// yet, plus a hint if we're inside a code fence (which buffers until
	// close so chroma can highlight the whole body).
	switch {
	case m.state == stateStreaming && m.liveTool != nil:
		// Tool cards are inherently multi-line; let them through. They
		// disappear when the tool finishes, but tools are infrequent so
		// the brief shrink doesn't accumulate visible artifacts.
		b.WriteString(renderLiveToolCard(*m.liveTool))
		b.WriteString("\n")
	case m.state == stateStreaming:
		var label string
		partial := strings.TrimRight(m.streamPartial, " \t")
		switch {
		case m.inFence:
			lang := strings.TrimSpace(m.fenceLang)
			if lang == "" {
				lang = "code"
			}
			head := "writing " + lang + " block…"
			if partial != "" {
				head += "  " + truncateForStatus(partial, m.width-len(head)-8)
			}
			label = styleStatus.Render("  ● " + head)
		case partial != "":
			label = styleStatus.Render("  ● ") + styleBody.Render(truncateForStatus(partial, m.width-4))
		case m.thinkingBuf != "":
			// Match the scrollback thinking card's ⋈ marker so the live
			// ticker reads as the same "channel" as the flushed block
			// that lands above when the reply starts streaming.
			label = styleStatus.Render("  " + terminal.SymbolBowtie + " thinking…")
		default:
			label = styleStatus.Render("  ● working…")
		}
		b.WriteString(label)
		b.WriteString("\n")
	default:
		b.WriteString("\n")
	}

	// Slash-command chooser — appears above the input the moment the user
	// types a leading "/", goes away as soon as they type past the command
	// name (a space or newline) or hit Esc. The popup grows the live region
	// while open; that's accepted because it's short-lived and entirely
	// driven by the user's own keystrokes.
	if chooser := m.renderSlashChooser(); chooser != "" {
		b.WriteString(chooser)
		b.WriteString("\n")
	}

	// Input box — always visible. Height is updated in Update() now (so the
	// textarea's internal viewport stays in sync with content); here we just
	// render whatever the textarea currently knows.
	b.WriteString(styleInputBorder.Render(m.input.View()))

	// Footer — persistent context: directory · tokens · model · effort (backend).
	// Keyboard hints live in the boot banner (shown once in scrollback), so the
	// footer can focus on state that's useful to glance at mid-session.
	b.WriteString("\n")
	b.WriteString(m.renderFooter())

	v := tea.NewView(b.String())
	// Ask the terminal to report key event types via the kitty keyboard
	// protocol. On terminals that support it (kitty, ghostty, wezterm,
	// recent iTerm2) shift+enter arrives as a distinct KeyPressMsg with
	// String()="shift+enter". On terminals that don't, the request is a
	// no-op and shift+enter still collapses to plain "enter".
	v.KeyboardEnhancements.ReportEventTypes = true
	return v
}

// --- Scrollback block rendering ---
//
// These functions produce a multi-line string that is emitted via
// tea.Printf and then persists in the terminal's normal scrollback.

// truncateForStatus shortens s to fit within max columns, trimming from the
// LEFT (so the most recently emitted text stays visible). Falls back to a
// 60-column window when max isn't yet known.
func truncateForStatus(s string, max int) string {
	if max <= 8 {
		max = 60
	}
	const ellipsis = "…"
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	keep := max - len([]rune(ellipsis))
	if keep < 1 {
		keep = 1
	}
	return ellipsis + string(r[len(r)-keep:])
}

const maxScrollbackChunkRows = 24

// printScrollback emits completed content above the live input area. Large
// writes are chunked because Bubble Tea's inline renderer can lose the live
// input when one insertAbove call is taller than the visible terminal.
func (m Model) printScrollback(s string) tea.Cmd {
	chunks := splitScrollbackChunks(s, m.width, maxScrollbackChunkRows)
	if len(chunks) == 0 {
		return nil
	}
	cmds := make([]tea.Cmd, 0, len(chunks)+1)
	for _, chunk := range chunks {
		chunk := chunk
		cmds = append(cmds, tea.Printf("%s", chunk))
	}
	if repaint := repaintCurrentSize(m.width, m.height); repaint != nil {
		cmds = append(cmds, repaint)
	}
	return tea.Sequence(cmds...)
}

func repaintCurrentSize(width, height int) tea.Cmd {
	if width <= 0 || height <= 0 {
		return nil
	}
	return func() tea.Msg {
		return tea.WindowSizeMsg{Width: width, Height: height}
	}
}

func splitScrollbackChunks(s string, width, maxRows int) []string {
	if s == "" {
		return nil
	}
	if width <= 8 {
		width = 80
	}
	if maxRows <= 0 {
		maxRows = maxScrollbackChunkRows
	}

	lines := strings.Split(s, "\n")
	chunks := make([]string, 0, 1+(len(lines)/maxRows))
	buf := make([]string, 0, maxRows)
	rows := 0
	for _, line := range lines {
		lineRows := visualRows(line, width)
		if len(buf) > 0 && rows+lineRows > maxRows {
			chunks = append(chunks, strings.Join(buf, "\n"))
			buf = buf[:0]
			rows = 0
		}
		buf = append(buf, line)
		rows += lineRows
	}
	if len(buf) > 0 {
		chunks = append(chunks, strings.Join(buf, "\n"))
	}
	return chunks
}

func visualRows(line string, width int) int {
	if width <= 0 {
		width = 80
	}
	w := lipgloss.Width(line)
	if w <= 0 {
		return 1
	}
	return ((w - 1) / width) + 1
}

// renderUserBlock formats a user prompt with the userRail glyph prefixed onto
// every line, so a multi-line message reads as a single grouped block without
// an extra "you" label. Each line's body is padded with a subtle background
// tint (colorUserBg) out to the terminal width so the user prompt looks like
// a chat bubble distinct from the assistant's reply, which renders on the
// default terminal background.
//
// userRail alternatives that look good in monospace: ▎ (lighter), ▏ (very
// thin), ┃ (heavy box), │ (light box), ║ (double), ❯ / › (angle), > (ASCII).
func renderUserBlock(prompt string, width int) string {
	rail := styleUserLabel.Render(userRail)
	body := styleUserBody
	if bodyWidth := width - lipgloss.Width(userRail); bodyWidth >= 20 {
		body = body.Width(bodyWidth)
	}
	lines := strings.Split(prompt, "\n")
	for i, line := range lines {
		lines[i] = rail + body.Render(line)
	}
	return strings.Join(lines, "\n")
}

// renderSlashChooser draws the /command popup that sits above the input. It's
// a bordered box listing every matching command, with the highlighted entry
// rendered bold + accent. Returns "" when the chooser is closed so the caller
// can skip emitting any extra rows.
//
// The label column is left-padded to the longest visible label so descriptions
// align in a clean second column.
func (m Model) renderSlashChooser() string {
	if !m.slashOpen || len(m.slashFiltered) == 0 {
		return ""
	}

	maxLabel := 0
	for _, it := range m.slashFiltered {
		if w := lipgloss.Width(it.label); w > maxLabel {
			maxLabel = w
		}
	}

	rows := make([]string, 0, len(m.slashFiltered)+1)
	rows = append(rows, styleHint.Render("commands  ·  ↑/↓ to navigate  ·  tab to autocomplete  ·  esc to dismiss"))
	for i, it := range m.slashFiltered {
		marker := "  "
		labelStyle := lipgloss.NewStyle().Foreground(colorText)
		if i == m.slashIdx {
			marker = lipgloss.NewStyle().Foreground(colorAccent).Render("▸ ")
			labelStyle = labelStyle.Bold(true).Foreground(colorAccent)
		}
		label := it.label + strings.Repeat(" ", maxLabel-lipgloss.Width(it.label))
		row := marker + labelStyle.Render(label)
		if it.description != "" {
			row += "  " + styleHint.Render(it.description)
		}
		rows = append(rows, row)
	}

	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorAccentDim).
		Padding(0, 1).
		Render(strings.Join(rows, "\n"))
}

// renderAssistant prints the assistant's markdown reply raw, except fenced
// code block bodies get Chroma syntax highlighting. Fence lines and all prose
// markdown markers remain visible so the user can copy the original content.
//
// On any chroma error (unknown lexer, format failure) we fall back to the
// fence's raw text via styleBody — never drop content.
func (m *Model) renderAssistant(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}

	lines := strings.Split(text, "\n")
	var b strings.Builder
	prose := make([]string, 0, len(lines))

	flushProse := func(addTrailingNewline bool) {
		if len(prose) == 0 {
			return
		}
		b.WriteString(renderProse(strings.Join(prose, "\n")))
		if addTrailingNewline {
			b.WriteString("\n")
		}
		prose = prose[:0]
	}

	for i := 0; i < len(lines); {
		lang, ok := parseFenceLine(lines[i])
		if !ok {
			prose = append(prose, lines[i])
			i++
			continue
		}

		closeIdx := findFenceClose(lines, i, lang)
		if closeIdx < 0 {
			prose = append(prose, lines[i])
			i++
			continue
		}

		flushProse(true)
		fence := strings.Join(lines[i:closeIdx+1], "\n")
		code := strings.Join(lines[i+1:closeIdx], "\n")
		b.WriteString(renderHighlightedFence(fence, lang, code))
		if closeIdx < len(lines)-1 {
			b.WriteString("\n")
		}
		i = closeIdx + 1
	}

	flushProse(false)
	return b.String()
}

func parseFenceLine(line string) (lang string, ok bool) {
	line = strings.TrimRight(line, "\r")
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "```") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(trimmed, "```")), true
}

func findFenceClose(lines []string, openIdx int, lang string) int {
	if isMarkdownLang(lang) {
		return findMarkdownFenceClose(lines, openIdx)
	}
	for i := openIdx + 1; i < len(lines); i++ {
		closeLang, ok := parseFenceLine(lines[i])
		if ok && strings.TrimSpace(closeLang) == "" {
			return i
		}
	}
	return -1
}

func findMarkdownFenceClose(lines []string, openIdx int) int {
	inNestedFence := false
	for i := openIdx + 1; i < len(lines); i++ {
		innerLang, ok := parseFenceLine(lines[i])
		if !ok {
			continue
		}
		innerLang = strings.TrimSpace(innerLang)
		if inNestedFence {
			if innerLang == "" {
				inNestedFence = false
			}
			continue
		}
		if innerLang != "" {
			inNestedFence = true
			continue
		}
		return i
	}
	return -1
}

// renderProse colors raw text with per-line markdown highlighting. Block-level
// classification (heading / bullet / numbered / quote) runs first, then inline
// tokens (bold, italic, strikethrough, inline code, links) are styled within
// each line. Only ANSI attributes are added — markdown markers remain visible
// so stripping ANSI returns the original source, and copy/paste still yields
// raw markdown.
func renderProse(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		lines[i] = renderProseLine(line)
	}
	return strings.Join(lines, "\n")
}

func renderProseLine(line string) string {
	if m := reMDHeading.FindStringSubmatch(line); m != nil {
		style := headingStyle(len(m[1]))
		return styleMDHMark.Render(m[1]) + style.Render(m[2]) + styleMDHMark.Render(m[3])
	}
	if m := reMDQuote.FindStringSubmatch(line); m != nil {
		return styleMDQuoteMark.Render(m[1]) + styleMDQuote.Render(m[2])
	}
	if m := reMDBullet.FindStringSubmatch(line); m != nil {
		return m[1] + styleMDListMark.Render(m[2]) + m[3] + renderInline(m[4])
	}
	if m := reMDNumbered.FindStringSubmatch(line); m != nil {
		return m[1] + styleMDListMark.Render(m[2]) + m[3] + renderInline(m[4])
	}
	return renderInline(line)
}

func headingStyle(level int) lipgloss.Style {
	switch level {
	case 1:
		return styleMDH1
	case 2:
		return styleMDH2
	default:
		return styleMDH3
	}
}

// renderInline walks s left-to-right, emitting styled spans for inline
// markdown constructs and body-colored plain text in between. Characters are
// preserved verbatim — only ANSI is added. Order of detection (code → bold →
// strikethrough → italic → link) matters so overlapping markers resolve to
// the widest sensible span (e.g. `**x**` is bold, not two italics).
func renderInline(s string) string {
	var b strings.Builder
	plain := 0
	flushPlain := func(end int) {
		if end > plain {
			b.WriteString(styleBody.Render(s[plain:end]))
		}
	}
	i := 0
	for i < len(s) {
		switch {
		case s[i] == '`':
			if j := strings.IndexByte(s[i+1:], '`'); j > 0 {
				end := i + 1 + j
				if !strings.ContainsRune(s[i+1:end], '\n') {
					flushPlain(i)
					b.WriteString(styleMDCode.Render(s[i : end+1]))
					i = end + 1
					plain = i
					continue
				}
			}
		case i+3 < len(s) && s[i] == '*' && s[i+1] == '*' && !isInlineSpace(s[i+2]):
			if end := findMarkerOnLine(s, i+2, "**"); end > i+2 && !isInlineSpace(s[end-1]) {
				flushPlain(i)
				b.WriteString(styleMDBold.Render(s[i : end+2]))
				i = end + 2
				plain = i
				continue
			}
		case i+3 < len(s) && s[i] == '~' && s[i+1] == '~' && !isInlineSpace(s[i+2]):
			if end := findMarkerOnLine(s, i+2, "~~"); end > i+2 && !isInlineSpace(s[end-1]) {
				flushPlain(i)
				b.WriteString(styleMDStrike.Render(s[i : end+2]))
				i = end + 2
				plain = i
				continue
			}
		case s[i] == '*' && i+1 < len(s) && !isInlineSpace(s[i+1]):
			if j := strings.IndexAny(s[i+1:], "*\n"); j > 0 && s[i+1+j] == '*' && !isInlineSpace(s[i+j]) {
				end := i + 1 + j
				flushPlain(i)
				b.WriteString(styleMDItalic.Render(s[i : end+1]))
				i = end + 1
				plain = i
				continue
			}
		case s[i] == '[':
			if loc := reMDLink.FindStringSubmatchIndex(s[i:]); loc != nil {
				textStart, textEnd := i+loc[2], i+loc[3]
				urlStart, urlEnd := i+loc[4], i+loc[5]
				matchEnd := i + loc[1]
				flushPlain(i)
				b.WriteString(styleMDLinkPunct.Render("["))
				b.WriteString(styleMDLinkText.Render(s[textStart:textEnd]))
				b.WriteString(styleMDLinkPunct.Render("]("))
				b.WriteString(styleMDLinkURL.Render(s[urlStart:urlEnd]))
				b.WriteString(styleMDLinkPunct.Render(")"))
				i = matchEnd
				plain = i
				continue
			}
		}
		i++
	}
	flushPlain(len(s))
	return b.String()
}

func findMarkerOnLine(s string, start int, marker string) int {
	for i := start; i <= len(s)-len(marker); i++ {
		if s[i] == '\n' {
			return -1
		}
		if strings.HasPrefix(s[i:], marker) {
			return i
		}
	}
	return -1
}

func isInlineSpace(b byte) bool {
	return b == ' ' || b == '\t'
}

// noHighlightLangs are language tags we deliberately do NOT pass through
// chroma. "markdown" is the big one: a fenced markdown block is usually a
// literal sample. Empty lang and generic "text"/"plain" tags get the same
// verbatim treatment for symmetry.
var noHighlightLangs = map[string]bool{
	"":          true,
	"text":      true,
	"plain":     true,
	"plaintext": true,
	"txt":       true,
	"markdown":  true,
	"md":        true,
}

func isMarkdownLang(lang string) bool {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "markdown", "md":
		return true
	default:
		return false
	}
}

func renderHighlightedFence(fence, lang, code string) string {
	opening, closing := splitFenceLines(fence)
	var b strings.Builder
	b.WriteString(styleMDMarker.Render(opening))
	b.WriteString("\n")
	if code != "" {
		b.WriteString(highlightCodeBlock(lang, code))
		b.WriteString("\n")
	}
	b.WriteString(styleMDMarker.Render(closing))
	return b.String()
}

func splitFenceLines(fence string) (opening, closing string) {
	lines := strings.Split(fence, "\n")
	if len(lines) == 0 {
		return "```", "```"
	}
	opening = strings.TrimRight(lines[0], "\r")
	closing = "```"
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimRight(lines[i], "\r")
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			closing = line
			break
		}
	}
	return opening, closing
}

// highlightCodeBlock runs Chroma over code fence bodies. Documentation-style
// languages bypass Chroma and indentation entirely so samples stay copyable.
func highlightCodeBlock(lang, code string) string {
	if noHighlightLangs[strings.ToLower(strings.TrimSpace(lang))] {
		return renderProse(code)
	}
	var buf strings.Builder
	if err := quick.Highlight(&buf, code, lang, "terminal256", "monokai"); err != nil {
		// Couldn't highlight — emit the raw block so the user still sees it.
		return indent(code, "  ")
	}
	return indent(strings.TrimRight(buf.String(), "\n"), "  ")
}

func renderToolBlock(name string, args map[string]any, result string, isErr bool) string {
	symbol := terminal.SymbolFunction
	if name == "bash" {
		symbol = terminal.SymbolBash
	}

	header := styleToolName.Render(symbol+" "+name) + "  " + styleToolArgs.Render(oneLineArgs(args))

	marker := styleToolOK.Render("  " + terminal.SymbolSuccess + " ")
	if isErr {
		marker = styleToolErr.Render("  " + terminal.SymbolError + " ")
	}
	body := marker + styleToolArgs.Render(truncateLines(result, 12, 4))

	return header + "\n" + body
}

// renderLiveToolCard is the in-flight variant shown in View() while a
// tool is executing. Same shape as renderToolBlock but with a spinner-ish
// marker and partial output.
func renderLiveToolCard(c liveTool) string {
	symbol := terminal.SymbolFunction
	if c.name == "bash" {
		symbol = terminal.SymbolBash
	}
	header := styleToolName.Render(symbol+" "+c.name) + "  " + styleToolArgs.Render(oneLineArgs(c.args))
	if c.partial != "" {
		return header + "\n" + styleToolArgs.Render("  … "+truncateLines(c.partial, 4, 4))
	}
	return header + "  " + styleToolArgs.Render("…")
}

func oneLineArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	var parts []string
	for k, v := range args {
		val := fmt.Sprintf("%v", v)
		val = strings.ReplaceAll(val, "\n", " ")
		if len(val) > 80 {
			val = val[:77] + "…"
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, val))
	}
	return "(" + strings.Join(parts, "  ") + ")"
}

// truncateLines trims a tool output to a maximum number of lines so
// scrollback stays readable. Indents every line with indentSpaces so
// the result drops neatly under a card header. The full content remains
// in Engine history if the user asks for it.
func truncateLines(s string, maxLines, indentSpaces int) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	pad := strings.Repeat(" ", indentSpaces)
	var kept []string
	if len(lines) <= maxLines {
		kept = lines
	} else {
		kept = append(kept, lines[:maxLines]...)
		omitted := len(lines) - maxLines
		kept = append(kept, styleHint.Render(fmt.Sprintf("… (%d more line%s)", omitted, plural(omitted))))
	}
	for i := range kept {
		kept[i] = pad + kept[i]
	}
	// Trim the leading padding on the first line — it sits right after the
	// marker on the same row, so extra spaces would look wrong.
	kept[0] = strings.TrimLeft(kept[0], " ")
	return strings.Join(kept, "\n")
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
