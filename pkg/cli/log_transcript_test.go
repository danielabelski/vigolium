package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// sampleTranscript is a minimal but representative transcript.jsonl: a session
// header, model change, a user turn, an assistant turn (thinking + text +
// toolCall), a tool result, and a terminal error.
const sampleTranscript = `{"type":"session","version":1,"id":"aaaa","timestamp":"2026-06-06T00:00:00Z","cwd":"/tmp"}
{"type":"model_change","id":"bbbb","parentId":null,"timestamp":"2026-06-06T00:00:01Z","provider":"openai-codex-oauth","modelId":"gpt-5.5"}
{"type":"message","id":"cccc","parentId":"bbbb","timestamp":"2026-06-06T00:00:02Z","message":{"role":"user","content":[{"type":"text","text":"scan https://ginandjuice.shop/"}],"timestamp":1}}
{"type":"message","id":"dddd","parentId":"cccc","timestamp":"2026-06-06T00:00:03Z","message":{"role":"assistant","content":[{"type":"thinking","thinking":"I should fetch the homepage first.\n\n\nThen enumerate."},{"type":"text","text":"Fetching the homepage to map the attack surface."},{"type":"toolCall","id":"call_1","name":"web_fetch","arguments":{"url":"https://ginandjuice.shop/","method":"GET"}}],"provider":"openai-codex-oauth","model":"gpt-5.5","timestamp":2}}
{"type":"message","id":"eeee","parentId":"dddd","timestamp":"2026-06-06T00:00:04Z","message":{"role":"toolResult","toolCallId":"call_1","toolName":"web_fetch","content":[{"type":"text","text":"<html><body>ok</body></html>"}],"isError":false,"timestamp":3}}
{"type":"error","id":"ffff","parentId":"eeee","timestamp":"2026-06-06T00:00:05Z","error":"codex stream error"}
`

func TestRenderTranscript(t *testing.T) {
	var buf bytes.Buffer
	if err := renderTranscript(&buf, strings.NewReader(sampleTranscript)); err != nil {
		t.Fatalf("renderTranscript: %v", err)
	}
	out := terminal.StripANSI(buf.String())

	for _, want := range []string{
		"◆ model: openai-codex-oauth gpt-5.5",
		"▸ user",
		"scan https://ginandjuice.shop/",
		"⋈ thinking",
		"I should fetch the homepage first.", // compacted (blank lines dropped)
		"Fetching the homepage to map the attack surface.",
		"▶ web_fetch",
		"method=GET", // args rendered, keys sorted (method before url)
		"url=https://ginandjuice.shop/",
		"✓ web_fetch",
		"bytes",
		"<html><body>ok</body></html>", // result preview
		"✖ error: codex stream error",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered transcript missing %q\n--- got ---\n%s", want, out)
		}
	}

	// Args are key-sorted: method must appear before url on the tool-call line.
	if i, j := strings.Index(out, "method=GET"), strings.Index(out, "url=https"); i < 0 || j < 0 || i > j {
		t.Errorf("expected sorted args (method before url); got indices %d, %d", i, j)
	}
}

func TestRenderTranscriptTruncatesLongLine(t *testing.T) {
	long := strings.Repeat("A", 5000)
	line := `{"type":"message","id":"x","message":{"role":"user","content":[{"type":"text","text":"` + long + `"}]}}` + "\n"

	var buf bytes.Buffer
	if err := renderTranscript(&buf, strings.NewReader(line)); err != nil {
		t.Fatalf("renderTranscript: %v", err)
	}
	out := terminal.StripANSI(buf.String())

	if strings.Contains(out, long) {
		t.Error("expected the 5000-char line to be truncated, but it printed in full")
	}
	if !strings.Contains(out, "…") {
		t.Error("expected an ellipsis marking the truncation")
	}
	// No single rendered line should exceed the width cap (+ a little slack for
	// the indent prefix and ellipsis).
	for _, l := range strings.Split(out, "\n") {
		if n := len([]rune(l)); n > transcriptMaxLineWidth+8 {
			t.Errorf("line exceeds width cap: %d runes", n)
		}
	}
}

func TestRenderTranscriptCapsBlockLines(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < transcriptMaxBlockLines+25; i++ {
		sb.WriteString("line\\n") // literal \n inside the JSON string
	}
	line := `{"type":"message","id":"x","message":{"role":"user","content":[{"type":"text","text":"` + sb.String() + `"}]}}` + "\n"

	var buf bytes.Buffer
	if err := renderTranscript(&buf, strings.NewReader(line)); err != nil {
		t.Fatalf("renderTranscript: %v", err)
	}
	out := terminal.StripANSI(buf.String())
	if !strings.Contains(out, "more line") {
		t.Errorf("expected a '… (N more lines)' trailer for the oversized block\n--- got ---\n%s", out)
	}
}

func TestRenderTranscriptSkipsMalformed(t *testing.T) {
	in := "not json at all\n" + `{"type":"message","message":{"role":"user","content":[{"type":"text","text":"valid"}]}}` + "\n"
	var buf bytes.Buffer
	if err := renderTranscript(&buf, strings.NewReader(in)); err != nil {
		t.Fatalf("renderTranscript: %v", err)
	}
	if out := terminal.StripANSI(buf.String()); !strings.Contains(out, "valid") {
		t.Errorf("expected the valid line to render despite a malformed predecessor; got %q", out)
	}
}

// The committed sample transcripts external tools parse against
// (test/testdata/agent-transcripts/README.md). These tests guard them against
// schema drift and confirm the shipped reader renders them. Regenerate with
// `go run ./test/testdata/agent-transcripts/generate.go`.
const (
	fixtureDir              = "../../test/testdata/agent-transcripts/"
	sampleTranscriptFixture = fixtureDir + "autopilot-transcript.jsonl"
	durableTranscriptFixt   = fixtureDir + "autopilot-durable-transcript.jsonl"
)

func TestRenderTranscriptFixture(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		wants []string // markers that must survive the render round trip
	}{
		{
			name: "autopilot",
			path: sampleTranscriptFixture,
			wants: []string{
				"◆ model: openai-codex-oauth gpt-5.4",
				"▸ user", "⋈ thinking", "▶ http_request", "✓ http_request",
				"✗", // the errored PATCH tool result
				"Horizontal IDOR/BOLA on GET /api/users/{id}",
			},
		},
		{
			name: "durable",
			path: durableTranscriptFixt,
			wants: []string{
				"◆ model: anthropic-oauth claude-opus-4-8",
				"⋈ thinking",
				"query_records to see the captured endpoints", // multi-line thinking body
				"▶ query_records", "▶ replay_request",
				"✗",                              // rate-limited sweep tool error
				"✖ error: provider stream error", // terminal engine error line
				"BOLA on GET /api/orders/{id}",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.FromSlash(tc.path))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			assertTranscriptStructure(t, raw)

			var buf bytes.Buffer
			if err := renderTranscript(&buf, bytes.NewReader(raw)); err != nil {
				t.Fatalf("renderTranscript(fixture): %v", err)
			}
			out := terminal.StripANSI(buf.String())
			for _, want := range tc.wants {
				if !strings.Contains(out, want) {
					t.Errorf("rendered fixture missing %q", want)
				}
			}
		})
	}
}

// assertTranscriptStructure verifies every non-empty line is valid JSON matching
// the Pi header trio + version and a linear parentId chain (session carries no
// parentId), with at least one assistant + toolResult message.
func assertTranscriptStructure(t *testing.T, raw []byte) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 5 {
		t.Fatalf("fixture unexpectedly short: %d lines", len(lines))
	}
	wantHeader := []string{"session", "model_change", "thinking_level_change"}
	var prevID string
	sawAssistant, sawToolResult := false, false
	for i, ln := range lines {
		var env struct {
			Type     string  `json:"type"`
			ID       string  `json:"id"`
			Version  int     `json:"version"`
			ParentID *string `json:"parentId"`
			Message  struct {
				Role string `json:"role"`
			} `json:"message"`
		}
		if err := json.Unmarshal([]byte(ln), &env); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", i+1, err, ln)
		}
		if i < len(wantHeader) && env.Type != wantHeader[i] {
			t.Errorf("line %d type = %q, want %q (header trio)", i+1, env.Type, wantHeader[i])
		}
		switch env.Type {
		case "session":
			if env.Version != 3 {
				t.Errorf("session version = %d, want 3", env.Version)
			}
			prevID = "" // chain restarts null at the next node
			continue
		case "message":
			switch env.Message.Role {
			case "assistant":
				sawAssistant = true
			case "toolResult":
				sawToolResult = true
			}
		}
		if prevID == "" {
			if env.ParentID != nil {
				t.Errorf("line %d (%s) parentId = %q, want null (chain head)", i+1, env.Type, *env.ParentID)
			}
		} else if env.ParentID == nil || *env.ParentID != prevID {
			t.Errorf("line %d (%s) parentId = %v, want %q (broken chain)", i+1, env.Type, env.ParentID, prevID)
		}
		prevID = env.ID
	}
	if !sawAssistant || !sawToolResult {
		t.Errorf("fixture missing message roles: assistant=%v toolResult=%v", sawAssistant, sawToolResult)
	}
}
