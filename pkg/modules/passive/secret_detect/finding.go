package secret_detect

import (
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/toolexec/kingfisher"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// SecretDedupKey builds the identity used to collapse duplicate secret findings:
// the same secret value (snippet), from the same rule, on the same URL is the
// same leak no matter how many times it is re-observed. The same page is fetched
// across discovery, spidering, targeted re-spider, and the dynamic-assessment
// baseline, so the passive module buffers — and Kingfisher re-matches — it once
// per pass, yielding several findings that differ only by a few dynamic bytes in
// the body. Deduping on (host, url, rule_id, snippet) keeps one finding per unique
// secret per URL, which stops near-identical request/response copies from piling
// up as redundant Additional Evidence when the storage layer later merges them.
// The same secret on a *different* URL keeps a distinct key (and is grouped by
// value later if warranted).
func SecretDedupKey(host, url, ruleID, snippet string) string {
	return host + "\x00" + url + "\x00" + ruleID + "\x00" + snippet
}

// NewSecretFinding builds the ResultEvent shared by both secret-finding emission
// paths — the passive module's batch flush and the known-issue-scan batch — so
// the two can't drift in title, tags, evidence, or metadata (they already did
// once: one path titled findings by rule ID, the other by rule name). Callers
// set the source-specific fields (ModuleID, ModuleType, FindingSource,
// ModuleShort, and any extra tags) on the returned event.
func NewSecretFinding(f *kingfisher.Finding, sev severity.Severity, conf severity.Confidence, host, url, request, response string) *output.ResultEvent {
	return &output.ResultEvent{
		Info: output.Info{
			Name:        f.RuleName(),
			Description: secretFindingDescription(f.RuleName(), f.Snippet()),
			Severity:    sev,
			Confidence:  conf,
			Tags:        []string{"secret", "credential", "exposure"},
		},
		Host:             host,
		URL:              url,
		Matched:          url,
		ExtractedResults: []string{f.Snippet()},
		Request:          request,
		Response:         response,
		Metadata: map[string]any{
			"rule_id":   f.RuleID(),
			"rule_name": f.RuleName(),
			"validated": f.IsValidated(),
			// Short, normalised classification of the secret (e.g. "JWT", "Google
			// API key"). The console renders it as a leading bracket before the
			// matched value; it also rides along in the jsonl/DB `meta` object for
			// triage.
			"pattern": PatternLabel(f.RuleName(), f.Snippet()),
		},
	}
}
