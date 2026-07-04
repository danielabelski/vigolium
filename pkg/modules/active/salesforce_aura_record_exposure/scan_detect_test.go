package salesforce_aura_record_exposure

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const contextHTML = `<html><head><script src="/s/sfsites/l/ABC123ctx~tok/app.js"></script></head><body>siteforce:communityApp</body></html>`

const configDataResp = `{"actions":[{"id":"123;a","state":"SUCCESS","returnValue":{"apiNamesToKeyPrefixes":` +
	`{"User":"005","Account":"001","Contact":"003","Broker__c":"a0X","Property__c":"a0Y"}}}]}`

// entityFromMessage decodes the entityNameOrId out of a getItems message.
func entityFromMessage(msg string) string {
	var m struct {
		Actions []struct {
			Params struct {
				EntityNameOrId string `json:"entityNameOrId"`
			} `json:"params"`
		} `json:"actions"`
	}
	_ = json.Unmarshal([]byte(msg), &m)
	if len(m.Actions) > 0 {
		return m.Actions[0].Params.EntityNameOrId
	}
	return ""
}

func recordsResp(total int) string {
	return `{"actions":[{"id":"123;a","state":"SUCCESS","returnValue":{"totalCount":` +
		itoa(total) + `,"result":[{"Id":"003xx","Name":"Jane Doe","Email":"jane@example.com"}]}}]}`
}

func emptyResp() string {
	return `{"actions":[{"id":"123;a","state":"SUCCESS","returnValue":{"totalCount":0,"result":[]}}]}`
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// auraServer emulates the Aura gateway. exposed is the set of object names whose
// getItems returns records; when catchAll is true every object (including the
// bogus probe) returns records.
func auraServer(t *testing.T, exposed map[string]bool, catchAll bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/s/" || r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(contextHTML))
		case strings.HasSuffix(r.URL.Path, "/aura"):
			msg := r.FormValue("message")
			if msg == "" || msg == "{}" {
				_, _ = w.Write([]byte(`{"event":{"descriptor":"markup://aura:invalidSession"}}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(msg, "getConfigData") {
				_, _ = w.Write([]byte(configDataResp))
				return
			}
			// getItems
			ent := entityFromMessage(msg)
			if catchAll || exposed[ent] {
				_, _ = w.Write([]byte(recordsResp(7)))
				return
			}
			_, _ = w.Write([]byte(emptyResp()))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func findByObject(results []*severityByName, obj string) *severityByName {
	for _, r := range results {
		if r.name == obj {
			return r
		}
	}
	return nil
}

type severityByName struct {
	name string
	sev  severity.Severity
}

func TestRecordExposureContactAndCustom(t *testing.T) {
	srv := auraServer(t, map[string]bool{"Contact": true, "Case": true, "Broker__c": true}, false)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	var got []*severityByName
	for _, res := range results {
		// Info.Name is "Salesforce Aura Guest Record Exposure: <obj>"
		parts := strings.SplitN(res.Info.Name, ": ", 2)
		if len(parts) == 2 {
			got = append(got, &severityByName{name: parts[1], sev: res.Info.Severity})
		}
	}

	if c := findByObject(got, "Contact"); c == nil || c.sev != severity.Critical {
		t.Fatalf("expected Contact Critical, got %+v", got)
	}
	if c := findByObject(got, "Case"); c == nil || c.sev != severity.Critical {
		t.Fatalf("expected Case Critical, got %+v", got)
	}
	if c := findByObject(got, "Broker__c"); c == nil || c.sev != severity.High {
		t.Fatalf("expected Broker__c High (custom object via getConfigData), got %+v", got)
	}
	// Property__c is enumerable but returns no records → must not fire.
	if p := findByObject(got, "Property__c"); p != nil {
		t.Fatalf("Property__c returns no records and must not fire, got %+v", got)
	}
}

func TestRecordExposureCatchAllRejected(t *testing.T) {
	// Every object (incl. the bogus probe) returns records → negative control
	// trips → no findings.
	srv := auraServer(t, nil, true)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("catch-all gateway must yield no findings, got %+v", results)
	}
}

func TestRecordExposureSkipsNonSalesforce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("non-Salesforce target must yield no findings, got %+v", results)
	}
}
