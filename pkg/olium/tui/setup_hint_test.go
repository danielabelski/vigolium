package tui

import "testing"

// TestLooksLikeSetupError pins the two halves of the gate: the credential /
// endpoint failures the setup guide fixes, and the runtime failures where a
// docs pointer would be noise (or actively misleading).
func TestLooksLikeSetupError(t *testing.T) {
	setup := []string{
		"anthropic-api-key: no key (set agent.olium.llm_api_key, $ANTHROPIC_API_KEY, --llm-api-key, or pick a different provider)",
		"anthropic-oauth: no token (set agent.olium.oauth_token, $ANTHROPIC_API_KEY, --oauth-token, or run `claude setup-token`)",
		"openai-api-key: key starts with sk-ant- (Anthropic shape)",
		`{"error":{"message":"invalid api key"}}`,
		"provider returned 401 Unauthorized",
		"HTTP 403 from api.anthropic.com",
		"anthropic-cli: \"claude\" not found on PATH (install Claude Code CLI or pass --claude-bin)",
		"openai-codex-oauth: open /home/u/.codex/auth.json: no such file or directory",
		"Post \"http://localhost:11434/v1/chat/completions\": dial tcp 127.0.0.1:11434: connect: connection refused",
		"dial tcp: lookup gateway.internal: no such host",
		"authentication_error: OAuth token has expired",
	}
	for _, msg := range setup {
		if !looksLikeSetupError(msg) {
			t.Errorf("looksLikeSetupError(%q) = false, want true", msg)
		}
	}

	runtime := []string{
		"exceeded max turns (32)",
		"context canceled",
		"context deadline exceeded",
		"tool bash failed: exit status 1",
		"stream ended without a stop reason",
		"",
	}
	for _, msg := range runtime {
		if looksLikeSetupError(msg) {
			t.Errorf("looksLikeSetupError(%q) = true, want false", msg)
		}
	}
}
