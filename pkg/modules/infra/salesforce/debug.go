package salesforce

import (
	"regexp"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// auraModeRe extracts the Aura framework "mode" declared in a Lightning
// bootstrap payload (the auraConfig / aura.context embedded in the page). The
// alternation is anchored to the known Aura mode enum so a random `"mode":"..."`
// in unrelated JSON on the page cannot match — and the family already gates on a
// live Aura gateway, so the page is genuinely a Lightning bootstrap.
var auraModeRe = regexp.MustCompile(`"mode"\s*:\s*"(PROD|PRODDEBUG|DEV|STATS|JSTEST|AUTOJSTEST|JSTESTDEBUG)"`)

// AuraMode returns the Aura framework mode declared in body (PROD, PRODDEBUG,
// DEV, …). ok is false when no Aura mode marker is present. Which modes
// constitute a finding is the consuming module's policy, not this parser's.
func AuraMode(body string) (mode string, ok bool) {
	m := auraModeRe.FindStringSubmatch(body)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// HarvestAuraMode fetches a community landing page and reads the Aura bootstrap
// mode from it. It is a fresh, cache-bypassed observation each call (saasprobe
// disables clustering), so a caller can invoke it across independent rounds for
// confirmation. ok is false when no page yields an Aura mode marker.
func HarvestAuraMode(ctx *httpmsg.HttpRequestResponse, client *http.Requester) (mode string, ok bool) {
	return harvestLandingPages(ctx, client, AuraMode)
}
