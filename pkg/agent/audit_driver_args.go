package agent

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
)

// ResolveAuditDriverInvocation derives the vigolium-audit agent + auth tuple
// from the configured olium provider and an optional override.
//
// Precedence:
//  1. providerOverride (CLI flag like --provider) — wins outright.
//  2. olium.Provider — anthropic-* → claude, openai-* → codex.
//  3. Default — claude (matches vigolium-audit's own default).
//
// Auth selection follows the resolved provider:
//   - anthropic-api-key  → APIKey from olium.LLMAPIKey
//   - anthropic-oauth    → OAuthToken from olium.OAuthToken
//   - anthropic-cli      → no override (subscription auth)
//   - openai-api-key     → APIKey from olium.LLMAPIKey
//   - openai-codex-oauth → OAuthCredFile from olium.OAuthCredPath
//   - vertex providers   → no override (audit doesn't authenticate
//     against Vertex itself; the user routes through Anthropic/OpenAI
//     via audit's own provider-detection path)
//
// authOverride (variadic for backwards compatibility) supplies a per-run
// BYOK bundle from the audit CLI/REST surface. When non-empty, it REPLACES
// the olium-derived auth wholesale (see ApplyAuthOverrideToAudit) — the
// resolved agent (claude/codex) still comes from providerOverride/olium.
// Only the first element is consulted; extras are ignored.
func ResolveAuditDriverInvocation(olium config.OliumConfig, providerOverride string, authOverride ...AuthOverride) AuditDriverInvocation {
	provider := strings.TrimSpace(providerOverride)
	if provider == "" {
		provider = strings.TrimSpace(olium.Provider)
	}

	inv := AuditDriverInvocation{Agent: auditAgentSelFromProvider(provider)}

	switch provider {
	case "anthropic-api-key", "openai-api-key":
		inv.Auth.APIKey = olium.LLMAPIKey
	case "anthropic-oauth":
		inv.Auth.OAuthToken = olium.OAuthToken
	case "openai-codex-oauth":
		inv.Auth.OAuthCredFile = olium.OAuthCredPath
	}

	if len(authOverride) > 0 {
		ApplyAuthOverrideToAudit(&inv, authOverride[0])
	}

	// vigolium-audit is launched via exec with no shell, so a configured
	// cred path like "~/.codex/auth.json" (the openai-codex-oauth default)
	// must be tilde/$ENV-expanded here — otherwise audit receives the
	// literal "~/..." string, can't open it, and exits early (status 2).
	// olium's own codex loader expands it (auth.resolveCodexAuthPath), so
	// without this the same config that works for autopilot/swarm/olium
	// fails only on the audit leg. No-op on already-absolute paths.
	if inv.Auth.OAuthCredFile != "" {
		inv.Auth.OAuthCredFile = config.ExpandPath(inv.Auth.OAuthCredFile)
	}

	return inv
}

// auditAgentSelFromProvider picks the audit `--agent` value for either
// an olium provider name or a direct audit agent name.
//
// Inputs come from two distinct call sites with different conventions:
//   - CLI's --provider flag → provider names (anthropic-*, openai-*,
//     google-*) which map by prefix to claude/codex.
//   - REST's req.Agent field      → direct agent names ("claude" | "codex")
//     validated upstream by IsValidAuditDriverPlatform.
//
// Direct agent names short-circuit the prefix mapping so REST's
// `agent:"codex"` resolves to codex instead of falling through to the
// default. Without this, REST callers were silently downgraded to claude,
// audit was launched with --agent claude using whatever cred file was in
// the auth override, and the bundle came back with claude artifacts even
// though the request asked for codex.
//
// anthropic-cli + anthropic-vertex still resolve to claude; openai-*
// resolve to codex. Unknown inputs fall back to claude (audit's own
// default) so a misspelled config doesn't error the launcher path —
// audit's own probe will surface the real error.
func auditAgentSelFromProvider(provider string) AuditDriverAgent {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch p {
	case string(AuditDriverAgentClaude):
		return AuditDriverAgentClaude
	case string(AuditDriverAgentCodex):
		return AuditDriverAgentCodex
	}
	switch {
	case strings.HasPrefix(p, "openai-"):
		return AuditDriverAgentCodex
	case strings.HasPrefix(p, "anthropic-"), strings.HasPrefix(p, "google-"):
		return AuditDriverAgentClaude
	default:
		return AuditDriverAgentClaude
	}
}

// ValidateAuditDriverInvocation checks that the resolved auth is usable by
// the resolved agent. A pure agent selector — the `--agent` flag or
// agent.audit.default_agent — flips inv.Agent while deliberately keeping
// the provider/BYOK-derived auth, so it can pair codex with an Anthropic
// OAuth token (claude-only), which vigolium-audit rejects mid-run. Catching
// it here turns that into a clear pre-flight error.
//
// Only the OAuthToken→claude rule is enforced, mirroring
// ValidateAuthOverride: API keys are agent-agnostic at this layer, and a
// codex cred file paired with claude is left to vigolium-audit so the
// documented "--agent keeps the resolved auth" contract is preserved.
// Returns nil when no auth is set or it is compatible.
func ValidateAuditDriverInvocation(inv AuditDriverInvocation) error {
	if inv.Auth.OAuthToken != "" && normalizedAgent(string(inv.Agent)) != string(AuditDriverAgentClaude) {
		return fmt.Errorf("oauth-token is claude-only but the audit agent resolved to %q — select claude (--agent claude or an anthropic-* provider/agent.audit.default_agent), or use --oauth-cred-file / --api-key for codex", normalizedAgent(string(inv.Agent)))
	}
	return nil
}

// IsValidAuditDriverAgent reports whether s is a recognized audit `--agent`
// value (claude|codex). Used by CLI / REST validation of the
// --provider override.
func IsValidAuditDriverAgent(s string) bool {
	switch AuditDriverAgent(s) {
	case AuditDriverAgentClaude, AuditDriverAgentCodex:
		return true
	}
	return false
}

// ForceAuditDriverAgent layers the CLI --agent flag on top of an already
// resolved invocation. It is a *pure agent selector*: when agentOverride
// is a valid audit agent (claude|codex) it replaces inv.Agent only,
// leaving the provider-derived auth on inv untouched. This is what makes
// `--provider <p> --agent <a>` keep <p>'s BYOK auth while running
// agent <a>. An empty or invalid override is a no-op, so the resolver's
// provider-derived agent stands (callers validate up front and surface a
// clear error for genuinely bad input).
func ForceAuditDriverAgent(inv *AuditDriverInvocation, agentOverride string) {
	if inv == nil {
		return
	}
	a := strings.ToLower(strings.TrimSpace(agentOverride))
	switch AuditDriverAgent(a) {
	case AuditDriverAgentClaude, AuditDriverAgentCodex:
		inv.Agent = AuditDriverAgent(a)
	}
}

// AuditDriverCLIAvailable reports whether the coding-agent CLI that
// vigolium-audit will drive (claude or codex) is on PATH for the given
// resolved agent. Empty defaults to claude (vigolium-audit's own default).
// Used by --driver=auto to skip the audit leg without launching the
// embedded binary when its required CLI is missing.
func AuditDriverCLIAvailable(a AuditDriverAgent) (string, bool) {
	name := string(a)
	if name == "" {
		name = string(AuditDriverAgentClaude)
	}
	_, err := exec.LookPath(name)
	return name, err == nil
}
