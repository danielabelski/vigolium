package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.SetWidth(msg.Width - 4)
		return m, nil

	case tea.KeyPressMsg:
		// v2 matches keys via String() — stable across terminals and across
		// any modifier permutation. The kitty keyboard protocol (auto-
		// negotiated by Bubble Tea v2 when the terminal advertises support)
		// is what makes "shift+enter" actually distinguishable from "enter".
		switch msg.String() {
		case "esc":
			// Priority: dismiss the slash chooser if it's open, otherwise
			// cancel an in-flight turn. Ctrl+C kills the whole program; Esc
			// is the softer "stop what you're doing, I want the prompt back"
			// affordance — matches the "escape interrupt" hint in the banner.
			if m.slashOpen {
				m.slashOpen = false
				return m, nil
			}
			if m.state == stateStreaming && m.cancel != nil {
				m.cancel()
				return m, nil
			}
		case "up":
			if m.slashOpen && len(m.slashFiltered) > 0 {
				m.slashIdx = (m.slashIdx - 1 + len(m.slashFiltered)) % len(m.slashFiltered)
				return m, nil
			}
		case "down":
			if m.slashOpen && len(m.slashFiltered) > 0 {
				m.slashIdx = (m.slashIdx + 1) % len(m.slashFiltered)
				return m, nil
			}
		case "tab":
			// Tab autocompletes the highlighted entry into the textarea. Only
			// intercept when the chooser is open; otherwise let the textarea
			// handle Tab as a literal character.
			if m.slashOpen && len(m.slashFiltered) > 0 {
				chosen := m.slashFiltered[m.slashIdx]
				m.input.SetValue(chosen.insertion)
				m.input.CursorEnd()
				m.refilterSlash()
				return m, nil
			}
		}
		switch msg.String() {
		case "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			// Cancelling the external context flags Bubble Tea's shutdown
			// as "killed", which skips the 500 ms waitForReadLoop timeout
			// on the TTY input reader. Keep tea.Quit as a fallback in case
			// Run() wasn't the one that created this Model.
			if m.cfg.quit != nil {
				m.cfg.quit()
			}
			return m, tea.Quit

		case "ctrl+j", "alt+enter", "shift+enter":
			// All three are "soft return" — insert a newline into the
			// textarea instead of submitting. ctrl+j works on every
			// terminal; alt+enter works wherever Option/Alt sends ESC;
			// shift+enter works on terminals that negotiate the kitty
			// keyboard protocol (kitty, ghostty, wezterm, recent iTerm2).
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
			m.resyncInputHeight()
			m.resetInputViewport()
			return m, cmd

		case "enter":
			// Backslash-at-end + Enter → strip backslash, insert newline.
			// Mirrors Claude Code / bash line-continuation habit; works on
			// every terminal.
			if strings.HasSuffix(m.input.Value(), `\`) {
				cur := m.input.Value()
				m.input.SetValue(cur[:len(cur)-1])
				// Move cursor to end and insert newline.
				m.input.CursorEnd()
				var cmd tea.Cmd
				m.input, cmd = m.input.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
				m.resyncInputHeight()
				m.resetInputViewport()
				return m, cmd
			}
			if m.state != stateIdle {
				return m, nil
			}
			prompt := strings.TrimSpace(m.input.Value())
			if prompt == "" {
				return m, nil
			}
			if prompt == "/clear" {
				m.cfg.Engine.Reset()
				m.resetStreamState()
				m.lastUsageLine = ""
				m.errMsg = ""
				m.input.Reset()
				m.resyncInputHeight()
				m.refilterSlash()
				// In inline mode, tea.ClearScreen only redraws the live view
				// (ultraviolet's clearUpdate does clearBelow(row=0) when not
				// fullscreen) — content that was pushed above via insertAbove
				// stays visible. ESC[3J alone just drops the off-screen
				// scrollback buffer, not the visible lines above the prompt.
				// Raw-writing H + 2J + 3J first scrubs the whole viewport and
				// scrollback, then tea.ClearScreen forces the renderer to
				// re-anchor the live view at the top of a blank screen before
				// the boot banner is re-inserted.
				return m, tea.Sequence(
					tea.Raw("\x1b[H\x1b[2J\x1b[3J"),
					tea.ClearScreen,
					m.printBootHeader(),
				)
			}
			if name, args, isSkill := skill.ParseInlineInvocation(prompt); isSkill {
				expanded, ok := skill.ExpandInlineInvocation(m.cfg.Skills, name, args)
				if !ok {
					m.errMsg = fmt.Sprintf("unknown skill %q — type a real skill name after /skill:", name)
					return m, nil
				}
				prompt = expanded
			}
			m.input.Reset()
			m.resyncInputHeight()
			m.refilterSlash()
			return m, func() tea.Msg { return sendMsg{prompt: prompt} }
		}

	case sendMsg:
		return m.startTurn(msg.prompt)

	case eventMsg:
		return m.applyEvent(engine.Event(msg))

	case runClosedMsg:
		m.state = stateIdle
		m.eventCh = nil
		if m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		m.resetStreamState()
		// Terminating blank line in scrollback — separates turns visually.
		return m, tea.Printf("")
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.resyncInputHeight()
	m.refilterSlash()
	return m, cmd
}

func pumpEvents(ch <-chan engine.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return runClosedMsg{}
		}
		return eventMsg(ev)
	}
}

func (m Model) applyEvent(ev engine.Event) (tea.Model, tea.Cmd) {
	var print tea.Cmd

	switch ev.Type {
	case engine.EventTextDelta:
		print = m.handleTextDelta(ev.Delta)

	case engine.EventThinkingDelta:
		m.thinkingBuf += ev.Delta

	case engine.EventToolCallStart:
		m.liveTool = &liveTool{
			id:   ev.ToolCallID,
			name: ev.ToolName,
			args: ev.ToolArgs,
		}

	case engine.EventToolExecStart:
		if m.liveTool == nil || m.liveTool.id != ev.ToolCallID {
			m.liveTool = &liveTool{id: ev.ToolCallID, name: ev.ToolName, args: ev.ToolArgs}
		} else {
			m.liveTool.args = ev.ToolArgs
		}

	case engine.EventToolExecProgress:
		if m.liveTool != nil && m.liveTool.id == ev.ToolCallID {
			m.liveTool.partial = ev.ToolResult
		}

	case engine.EventToolExecEnd:
		// Flush the tool card to scrollback.
		card := renderToolBlock(ev.ToolName, ev.ToolArgs, ev.ToolResult, ev.ToolIsErr)
		print = m.printScrollback(card)
		if m.liveTool != nil && m.liveTool.id == ev.ToolCallID {
			m.liveTool = nil
		}

	case engine.EventTurnDone:
		// Streaming has already pushed completed prose lines and closed
		// fences into scrollback as they arrived. All that's left to drain
		// is: thinking buffered for a turn that never produced text (rare —
		// usually a tool-only turn), an unclosed fence, and the final
		// partial line that was still in flight.
		var prints []tea.Cmd
		if m.thinkingBuf != "" {
			prints = append(prints, m.printScrollback(m.renderThinkingBlock()))
			m.thinkingBuf = ""
		}
		if m.inFence {
			prints = append(prints, m.printScrollback(m.drainUnclosedFence()))
		}
		if m.streamPartial != "" {
			prints = append(prints, m.printScrollback(renderProseLine(m.streamPartial)))
			m.streamPartial = ""
		}
		m.thinkingFlushed = false
		if len(prints) > 0 {
			print = tea.Sequence(prints...)
		}
		if ev.Usage != nil {
			m.lastUsageLine = fmt.Sprintf("in %d · out %d · cached %d",
				ev.Usage.Input, ev.Usage.Output, ev.Usage.CacheRead)
		}

	case engine.EventRunDone:
		// handled on runClosedMsg

	case engine.EventError:
		m.errMsg = ev.Err
		print = m.printScrollback(styleErr.Render(terminal.SymbolError + " " + ev.Err))
	}

	pump := tea.Cmd(nil)
	if m.eventCh != nil {
		pump = pumpEvents(m.eventCh)
	}
	if print != nil {
		return m, tea.Sequence(print, pump)
	}
	return m, pump
}

// handleTextDelta consumes a chunk of streamed assistant text, flushing every
// completed line to scrollback as it arrives. The trailing partial (everything
// after the last `\n`) stays in m.streamPartial and is rendered as the live
// ticker until either more text arrives to complete it or the turn ends.
//
// Fenced code blocks are buffered: chroma needs the whole body to highlight,
// so a ```lang opener flips inFence and every subsequent line goes into
// fenceBuf until the closing fence arrives, at which point the entire fence
// flushes as one highlighted block.
//
// Thinking that was buffered before this delta is flushed first, so the user
// reads top-down: think → answer.
func (m *Model) handleTextDelta(delta string) tea.Cmd {
	var prints []tea.Cmd
	if !m.thinkingFlushed && m.thinkingBuf != "" {
		prints = append(prints, m.printScrollback(m.renderThinkingBlock()))
		m.thinkingBuf = ""
		m.thinkingFlushed = true
	}

	combined := m.streamPartial + delta
	parts := strings.Split(combined, "\n")
	m.streamPartial = parts[len(parts)-1]
	completeLines := parts[:len(parts)-1]

	var proseBatch []string
	flushProse := func() {
		if len(proseBatch) > 0 {
			prints = append(prints, m.printScrollback(strings.Join(proseBatch, "\n")))
			proseBatch = nil
		}
	}

	for _, line := range completeLines {
		if m.inFence {
			block, closed := m.feedFence(line)
			if closed {
				prints = append(prints, m.printScrollback(block))
			}
			continue
		}
		if lang, ok := parseFenceLine(line); ok {
			// Opening fence — flush any pending prose first so the fence
			// drops cleanly under the prose that came before it.
			flushProse()
			m.inFence = true
			m.fenceLang = lang
			m.fenceOpenLine = line
			m.fenceBuf = nil
			m.mdFenceNested = false
			continue
		}
		proseBatch = append(proseBatch, renderProseLine(line))
	}
	flushProse()

	if len(prints) == 0 {
		return nil
	}
	return tea.Sequence(prints...)
}

// feedFence consumes one line while inside a fenced code block. When the line
// closes the fence, returns (rendered block, true); otherwise the line is
// appended to fenceBuf and the call returns ("", false). The close rule
// mirrors findFenceClose / findMarkdownFenceClose so streaming and batch
// rendering produce the same fence boundaries.
func (m *Model) feedFence(line string) (string, bool) {
	innerLang, isFence := parseFenceLine(line)
	if !isFence {
		m.fenceBuf = append(m.fenceBuf, line)
		return "", false
	}
	innerLang = strings.TrimSpace(innerLang)
	if isMarkdownLang(m.fenceLang) {
		// Markdown-language fences nest: an inner fence with a lang opens a
		// nested block; only an empty-lang fence at depth 0 closes the outer
		// markdown block.
		if m.mdFenceNested {
			if innerLang == "" {
				m.mdFenceNested = false
			}
			m.fenceBuf = append(m.fenceBuf, line)
			return "", false
		}
		if innerLang != "" {
			m.mdFenceNested = true
			m.fenceBuf = append(m.fenceBuf, line)
			return "", false
		}
		return m.finishFence(line), true
	}
	if innerLang == "" {
		return m.finishFence(line), true
	}
	// Fence-like line carrying a lang inside a non-markdown fence is just
	// content — findFenceClose only treats empty-lang fences as closers.
	m.fenceBuf = append(m.fenceBuf, line)
	return "", false
}

// finishFence renders the buffered fence (opener + body + closer) via chroma
// and resets the fence state. The opener / closer lines are kept verbatim so
// users see the original ```lang they wrote.
func (m *Model) finishFence(closingLine string) string {
	parts := make([]string, 0, len(m.fenceBuf)+2)
	parts = append(parts, m.fenceOpenLine)
	parts = append(parts, m.fenceBuf...)
	parts = append(parts, closingLine)
	fence := strings.Join(parts, "\n")
	code := strings.Join(m.fenceBuf, "\n")
	lang := m.fenceLang
	m.inFence = false
	m.fenceLang = ""
	m.fenceOpenLine = ""
	m.fenceBuf = nil
	m.mdFenceNested = false
	return renderHighlightedFence(fence, lang, code)
}

// drainUnclosedFence is the EventTurnDone fallback for when the model stopped
// without closing a fence. We emit the opener + buffered lines as raw prose so
// nothing is dropped; chroma is skipped because the body is incomplete.
func (m *Model) drainUnclosedFence() string {
	lines := make([]string, 0, len(m.fenceBuf)+1)
	lines = append(lines, m.fenceOpenLine)
	lines = append(lines, m.fenceBuf...)
	out := renderProse(strings.Join(lines, "\n"))
	m.inFence = false
	m.fenceLang = ""
	m.fenceOpenLine = ""
	m.fenceBuf = nil
	m.mdFenceNested = false
	return out
}

// renderThinkingBlock formats the buffered reasoning stream as a tight,
// muted-italic block prefixed by the ⋈ bowtie so it reads as its own
// conversational lane (distinct from the user's ▶ rail and the assistant's
// default body). The thinking lane is a status channel, not prose — the
// reader wants to know *what* the model is reasoning about, not a faithful
// reproduction of paragraph structure. compactThinkingBody drops blank
// rows entirely and trims each surviving line, so a GPT-5-style reasoning
// summary ("**Title**\n\n\n\n\n\n\n\nBody…") renders as two adjacent lines
// instead of an empty half-page between them. Returns "" when nothing
// survives compaction so the caller skips the scrollback push.
func (m *Model) renderThinkingBlock() string {
	body := compactThinkingBody(m.thinkingBuf)
	if body == "" {
		return ""
	}
	header := styleThinking.Render("  " + terminal.SymbolBowtie + " thinking")
	return header + "\n" + styleThinking.Render(indent(body, "    "))
}

// compactThinkingBody trims each line and drops every blank line. "Blank"
// means empty *after* stripping Unicode whitespace — so tabs, non-breaking
// spaces, and any other IsSpace-class padding all collapse. We don't
// preserve paragraph breaks because the thinking lane is faint/italic
// status text, and GPT-5's reasoning summaries in particular embed huge
// runs of newlines between title and body that otherwise blow the block
// up into dead space.
func compactThinkingBody(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return strings.Join(out, "\n")
}

// resetStreamState wipes per-turn streaming buffers so a stray partial / open
// fence from a prior turn never leaks into the next one.
func (m *Model) resetStreamState() {
	m.streamPartial = ""
	m.inFence = false
	m.fenceLang = ""
	m.fenceOpenLine = ""
	m.fenceBuf = nil
	m.mdFenceNested = false
	m.thinkingBuf = ""
	m.thinkingFlushed = false
	m.liveTool = nil
}
