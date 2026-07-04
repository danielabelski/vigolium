package servicenow

import (
	"encoding/json"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/saasprobe"
)

// Verbatim out-of-the-box widget sys_ids (stable across instances). The Simple
// List widget dumps arbitrary table rows; the KB Article Page widget serves
// knowledge-base article bodies.
const (
	WidgetBase         = "/api/now/sp/widget/"
	SimpleListSysID    = "5b255672cb03020000f8d856634c9c28"
	SimpleListName     = "widget-simple-list"
	UnorderedListName  = "widget-unordered-list"
	KBArticlePageSysID = "c6545050ff223100ba13ffffffffffe8"
)

// SimpleListEndpoints are the widget locations tried for table dumping, most
// stable (sys_id) first.
var SimpleListEndpoints = []string{
	WidgetBase + SimpleListSysID,
	WidgetBase + SimpleListName,
	WidgetBase + UnorderedListName,
}

// WidgetResult is the Service Portal widget POST result (HTTP status + parsed
// data). Status is surfaced so callers can treat 401 as a token failure rather
// than evidence.
type WidgetResult struct {
	Status int
	OK     bool
	Data   *SimpleListData
}

// SimpleListData is the widget's returned record set. Only the fields consulted
// by SimpleListExposed / FirstDisplayValue are decoded; the widget returns more
// per row (sys_id, className, secondary_fields) that this detector does not use.
type SimpleListData struct {
	IsValid bool `json:"isValid"`
	Count   int  `json:"count"`
	List    []struct {
		DisplayField struct {
			DisplayValue json.RawMessage `json:"display_value"`
		} `json:"display_field"`
	} `json:"list"`
}

// widgetEnvelope handles both wrappings seen in the wild: a top-level "data"
// object and a REST "result.data" object.
type widgetEnvelope struct {
	Data   *SimpleListData `json:"data"`
	Result *struct {
		Data *SimpleListData `json:"data"`
	} `json:"result"`
}

func (w widgetEnvelope) list() *SimpleListData {
	if w.Data != nil {
		return w.Data
	}
	if w.Result != nil && w.Result.Data != nil {
		return w.Result.Data
	}
	return nil
}

// PostSimpleList calls a Simple List widget endpoint for one table/field with the
// guest session + CSRF token. field may be "" (widget defaults to the table's
// display column).
func PostSimpleList(ctx *httpmsg.HttpRequestResponse, client *http.Requester, endpoint, table, field string, s Session) WidgetResult {
	path := endpoint + "?t=" + table
	if field != "" {
		path += "&f=" + field
	}
	res := saasprobe.Post(ctx, client, path, "{}", widgetHeaders(s))
	if !res.OK {
		return WidgetResult{}
	}
	out := WidgetResult{Status: res.Status, OK: true}
	if env, ok := parseWidget(res.Body); ok {
		out.Data = env
	}
	return out
}

// KBData is the KB Article Page widget's returned article. Only the content
// fields KBExposed inspects are decoded (the widget also returns kbName, sys_id,
// author, rating, etc.).
type KBData struct {
	ShortDescription string `json:"short_description"`
	Text             string `json:"text"`
}

type kbEnvelope struct {
	Data   *KBData `json:"data"`
	Result *struct {
		Data *KBData `json:"data"`
	} `json:"result"`
}

func (k kbEnvelope) article() *KBData {
	if k.Data != nil {
		return k.Data
	}
	if k.Result != nil && k.Result.Data != nil {
		return k.Result.Data
	}
	return nil
}

// KBResult is the KB widget POST result.
type KBResult struct {
	Status int
	OK     bool
	Data   *KBData
}

// PostKBArticle calls the KB Article Page widget for one article id (a KB number
// like KB0000001, or a sys_id).
func PostKBArticle(ctx *httpmsg.HttpRequestResponse, client *http.Requester, articleID string, s Session) KBResult {
	path := WidgetBase + KBArticlePageSysID + "?sys_id=" + articleID
	res := saasprobe.Post(ctx, client, path, "{}", widgetHeaders(s))
	if !res.OK {
		return KBResult{}
	}
	out := KBResult{Status: res.Status, OK: true}
	var env kbEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Body)), &env); err == nil {
		out.Data = env.article()
	}
	return out
}

// SimpleListExposed reports whether a widget result evidences a real data leak:
// a valid response with a positive count and a first record whose display_value
// is a genuine, non-null value. Empty list / count 0 / null display_value are
// the false-positive guards (ACL denied rows, or a field-level block).
func SimpleListExposed(d *SimpleListData) bool {
	if d == nil || !d.IsValid || d.Count <= 0 || len(d.List) == 0 {
		return false
	}
	dv := strings.TrimSpace(string(d.List[0].DisplayField.DisplayValue))
	return dv != "" && dv != "null" && dv != `""`
}

// KBExposed reports whether a KB widget result carries article content.
func KBExposed(d *KBData) bool {
	if d == nil {
		return false
	}
	return strings.TrimSpace(d.Text) != "" || strings.TrimSpace(d.ShortDescription) != ""
}

// FirstDisplayValue returns the display_value string of the first record, for
// evidence (already confirmed non-null by SimpleListExposed).
func FirstDisplayValue(d *SimpleListData) string {
	if d == nil || len(d.List) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(d.List[0].DisplayField.DisplayValue, &s); err == nil {
		return s
	}
	return strings.Trim(string(d.List[0].DisplayField.DisplayValue), `"`)
}

func widgetHeaders(s Session) map[string]string {
	h := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}
	if s.Token != "" {
		h["X-UserToken"] = s.Token
	}
	if s.Cookie != "" {
		h["Cookie"] = s.Cookie
	}
	return h
}

func parseWidget(body string) (*SimpleListData, bool) {
	var env widgetEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &env); err != nil {
		return nil, false
	}
	d := env.list()
	if d == nil {
		return nil, false
	}
	return d, true
}
