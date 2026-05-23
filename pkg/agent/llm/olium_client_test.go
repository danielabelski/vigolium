package llm

import (
	"strings"
	"testing"
)

func TestSplitMessages_SingleUserPassesThrough(t *testing.T) {
	system, prompt := splitMessages(CompletionRequest{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if system != "" {
		t.Errorf("expected empty system, got %q", system)
	}
	if prompt != "hello" {
		t.Errorf("expected verbatim prompt %q, got %q", "hello", prompt)
	}
}

func TestSplitMessages_SystemSeparated(t *testing.T) {
	system, prompt := splitMessages(CompletionRequest{
		Messages: []Message{
			{Role: "system", Content: "be terse"},
			{Role: "user", Content: "ping"},
		},
	})
	if system != "be terse" {
		t.Errorf("expected system %q, got %q", "be terse", system)
	}
	// A lone non-system message is passed through without a role label.
	if prompt != "ping" {
		t.Errorf("expected unlabelled prompt %q, got %q", "ping", prompt)
	}
}

func TestSplitMessages_MultiTurnLabelled(t *testing.T) {
	_, prompt := splitMessages(CompletionRequest{
		Messages: []Message{
			{Role: "user", Content: "hi"},
			{Role: "assistant", Content: "hello"},
			{Role: "user", Content: "bye"},
		},
	})
	for _, want := range []string{"User: hi", "Assistant: hello", "User: bye"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("multi-turn prompt missing %q; got:\n%s", want, prompt)
		}
	}
}

func TestSplitMessages_MultipleSystemJoined(t *testing.T) {
	system, _ := splitMessages(CompletionRequest{
		Messages: []Message{
			{Role: "system", Content: "rule one"},
			{Role: "system", Content: "rule two"},
			{Role: "user", Content: "go"},
		},
	})
	if !strings.Contains(system, "rule one") || !strings.Contains(system, "rule two") {
		t.Errorf("expected both system rules joined, got %q", system)
	}
}

func TestAppendJSONInstruction(t *testing.T) {
	// Empty system → instruction is the whole prompt and references the schema.
	got := appendJSONInstruction("", `{"type":"object"}`)
	if !strings.Contains(got, `{"type":"object"}`) {
		t.Errorf("instruction dropped the schema: %q", got)
	}

	// Non-empty system → original system is preserved ahead of the instruction.
	got = appendJSONInstruction("keep me", `{"type":"array"}`)
	if !strings.HasPrefix(got, "keep me") {
		t.Errorf("expected existing system preserved at front, got %q", got)
	}
	if !strings.Contains(got, `{"type":"array"}`) {
		t.Errorf("instruction dropped the schema: %q", got)
	}
}

func TestNewOliumClient_NilConfig(t *testing.T) {
	if _, err := NewOliumClient(nil); err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}
