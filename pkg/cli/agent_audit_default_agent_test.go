package cli

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
)

// TestResolveAuditDriverInvocation_DefaultAgentPrecedence pins the precedence
// of agent.audit.default_agent relative to the per-run --agent / --provider
// flags. Highest first: --agent > --provider > default_agent >
// olium.provider-derived. default_agent applies only when neither flag pinned
// the agent this run.
func TestResolveAuditDriverInvocation_DefaultAgentPrecedence(t *testing.T) {
	saveProvider, saveAgent := auditProvider, auditAgent
	t.Cleanup(func() { auditProvider, auditAgent = saveProvider, saveAgent })

	// anthropic-cli resolves to claude with no auth override, so any codex
	// result below proves default_agent / a flag flipped the agent.
	olium := config.OliumConfig{Provider: "anthropic-cli"}

	cases := []struct {
		name         string
		flagProvider string
		flagAgent    string
		defaultAgent string
		want         agent.AuditDriverAgent
	}{
		{"default_agent codex applies when no flags", "", "", "codex", agent.AuditDriverAgentCodex},
		{"empty default_agent inherits provider (claude)", "", "", "", agent.AuditDriverAgentClaude},
		{"--agent wins over default_agent", "", "claude", "codex", agent.AuditDriverAgentClaude},
		{"--provider suppresses default_agent", "openai-codex-oauth", "", "claude", agent.AuditDriverAgentCodex},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			auditProvider = c.flagProvider
			auditAgent = c.flagAgent
			inv := resolveAuditDriverInvocation(olium, c.defaultAgent, agent.AuthOverride{})
			if inv.Agent != c.want {
				t.Errorf("agent = %q, want %q", inv.Agent, c.want)
			}
		})
	}
}

// TestDefaultAgent_DoesNotAffectBYOKAuth is the guarantee the user asked for:
// agent.audit.default_agent is a pure agent selector — it flips which agent
// runs but never touches the resolved auth. So a BYOK bundle (and the
// provider-derived auth) is forwarded identically whether or not
// default_agent is set; only inv.Agent changes.
func TestDefaultAgent_DoesNotAffectBYOKAuth(t *testing.T) {
	saveProvider, saveAgent := auditProvider, auditAgent
	t.Cleanup(func() { auditProvider, auditAgent = saveProvider, saveAgent })
	auditProvider, auditAgent = "", "" // no per-run flags, so default_agent applies

	// anthropic-cli derives to claude with no auth; the BYOK api-key supplies
	// the auth and would normally pair with claude.
	olium := config.OliumConfig{Provider: "anthropic-cli"}
	byok := agent.AuthOverride{APIKey: "sk-byok-key", Agent: "claude"}

	base := resolveAuditDriverInvocation(olium, "", byok)         // default_agent unset → claude
	flipped := resolveAuditDriverInvocation(olium, "codex", byok) // default_agent=codex → codex

	if base.Agent != agent.AuditDriverAgentClaude {
		t.Fatalf("base agent = %q, want claude", base.Agent)
	}
	if flipped.Agent != agent.AuditDriverAgentCodex {
		t.Fatalf("flipped agent = %q, want codex", flipped.Agent)
	}
	// The decisive assertion: the auth is byte-for-byte identical regardless
	// of default_agent. default_agent must never reroute or drop BYOK creds.
	if base.Auth != flipped.Auth {
		t.Fatalf("default_agent altered auth: base=%+v flipped=%+v", base.Auth, flipped.Auth)
	}
	if flipped.Auth.APIKey != "sk-byok-key" {
		t.Errorf("BYOK api key not forwarded under default_agent=codex: %+v", flipped.Auth)
	}

	// And a codex cred file composes cleanly with default_agent=codex
	// (agent and auth agree → no mismatch).
	credInv := resolveAuditDriverInvocation(
		config.OliumConfig{Provider: "openai-compatible"},
		"codex",
		agent.AuthOverride{OAuthCredFile: "/tmp/codex-auth.json", Agent: "codex"},
	)
	if credInv.Agent != agent.AuditDriverAgentCodex {
		t.Errorf("agent = %q, want codex", credInv.Agent)
	}
	if credInv.Auth.OAuthCredFile != "/tmp/codex-auth.json" {
		t.Errorf("BYOK cred file not forwarded: %q", credInv.Auth.OAuthCredFile)
	}
	if err := agent.ValidateAuditDriverInvocation(credInv); err != nil {
		t.Errorf("codex + cred file should validate, got: %v", err)
	}
}
