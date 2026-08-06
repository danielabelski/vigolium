package dependent_response

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "dependent-response"
	ModuleName  = "Referer / User-Agent Dependent Response"
	ModuleShort = "Detects responses that change based on a spoofable Referer or User-Agent header"
)

var (
	ModuleDesc = `**What it means:** The application returns materially different content depending on a client-controlled, easily-spoofed header — the Referer or the User-Agent. Any gating based on these headers is ineffective, and the differing behaviour can hide functionality (cloaking) or reveal weak access control.

**How it's exploited:** An attacker sets the header to whatever unlocks the alternate behaviour — impersonating a crawler to read bot-only content, or forging a Referer to bypass a referer check. Cloaked content also hides malicious behaviour from reviewers.

**Fix:** Do not vary security-relevant responses on the Referer or User-Agent header; treat both as untrusted.`

	ModuleConfirmation = "Confirmed when the response differs materially between two values of the header, and each variant reproduces stably across repeat requests (ruling out dynamic-content noise)"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"recon", "behavior", "cloaking", "moderate"}
)
