// Package salesforce holds shared detection and Aura-protocol helpers for the
// salesforce_* scanner family (Salesforce Experience Cloud / Lightning
// "community" sites served through the Aura gateway).
//
// The exposure class is a misconfigured Guest User profile: an Experience Cloud
// site grants the unauthenticated Guest user object/field read (or exposes an
// Apex method) that lets an attacker invoke Aura actions against a public gateway
// (/aura, /s/sfsites/aura, …) and enumerate/extract SObject records. This
// package centralizes the live Aura-gateway probe and the Aura wire protocol
// (context harvest, action invocation, response-envelope parsing) the active
// modules key on; locating a live gateway via Prepare is itself the fail-closed
// presence gate.
package salesforce

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/saasprobe"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Tag / TagLightning are the tech-stack tags published for Salesforce hosts.
const (
	Tag          = "salesforce"
	TagLightning = "lightning"
)

// VendorHostSuffixes are default Salesforce-hosted domains. A host under one of
// these is Salesforce by definition (fingerprint only — an exposed Aura gateway
// is still confirmed separately by the active modules).
var VendorHostSuffixes = []string{
	".force.com",
	".salesforce.com",
	".my.salesforce.com",
	".lightning.force.com",
	".secure.force.com",
	".my.site.com",
	".site.com",
	".live.siteforce.com",
	".salesforce-experience.com",
}

// AuraGatewayPaths are the well-known Aura endpoint locations. Experience Cloud
// sites usually expose /s/sfsites/aura; Visualforce/Site orgs use /aura or
// /sfsites/aura.
var AuraGatewayPaths = []string{
	"/s/sfsites/aura",
	"/sfsites/aura",
	"/aura",
	"/s/aura",
}

// strongBodyMarkers are single-hit Salesforce Aura/Lightning proofs.
var strongBodyMarkers = []string{
	"aura:invalidSession",
	"siteforce:communityApp",
	"/s/sfsites/l/",
	"window.Aura",
	"auraConfig",
	`"fwuid"`,
	"sfdcBaseURL",
}

// mediumBodyMarkers are weaker on their own, so Salesforce is only inferred from
// the body when at least two co-occur.
var mediumBodyMarkers = []string{
	"data-aura-rendered-by",
	"forceCommunity",
	"aura_prod",
	"/sfsites/c/",
	"LightningExperience",
}

// MatchResponse reports whether a response looks like Salesforce and which
// signals fired. It is used by the passive fingerprint; the active modules gate
// on a live Aura-gateway probe (Prepare), not on these body markers.
func MatchResponse(body string) (ok bool, signals []string) {
	strong := false
	for _, m := range strongBodyMarkers {
		if strings.Contains(body, m) {
			strong = true
			signals = append(signals, "body marker: "+m)
		}
	}
	mediumHits := 0
	for _, m := range mediumBodyMarkers {
		if strings.Contains(body, m) {
			mediumHits++
			signals = append(signals, "body marker: "+m)
		}
	}
	return strong || mediumHits >= 2, signals
}

// FindLiveAuraGateway POSTs an empty body to each candidate gateway path and
// returns the first that answers with the Aura framework's session error
// (aura:invalidSession / clientOutOfSync) — the definitive signal that a live
// Aura gateway is mounted at that path. Returns ("", false) when none respond.
func FindLiveAuraGateway(ctx *httpmsg.HttpRequestResponse, client *http.Requester) (string, bool) {
	for _, p := range AuraGatewayPaths {
		res := saasprobe.Post(ctx, client, p, "{}", map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		})
		if !res.OK {
			continue
		}
		if strings.Contains(res.Body, "aura:invalidSession") ||
			strings.Contains(res.Body, "aura:clientOutOfSync") ||
			strings.Contains(res.Body, "markup://aura:") {
			return p, true
		}
	}
	return "", false
}

// MarkSalesforce records Salesforce in the tech registry for host. The active
// modules call it after Prepare finds a live Aura gateway — locating the gateway
// IS the fail-closed presence gate (a non-Salesforce host has none), so there is
// no separate Confirm step that would re-probe the gateway.
func MarkSalesforce(sc *modkit.ScanContext, host string) {
	if sc == nil || host == "" {
		return
	}
	sc.MarkTech(host, Tag)
	sc.MarkTech(host, TagLightning)
	sc.MarkTech(host, "aura")
}

func hostOf(ctx *httpmsg.HttpRequestResponse) string {
	urlx, err := ctx.URL()
	if err != nil {
		return ""
	}
	return urlx.Host
}
