package salesforce_aura_object_exposure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const contextHTML = `<html><head><script src="/s/sfsites/l/ABC123ctx~tok/app.js"></script></head><body>siteforce:communityApp</body></html>`

// auraServer emulates the Aura gateway. configData is the getConfigData SUCCESS
// body returned on every action; an empty gateway probe returns invalidSession.
func auraServer(t *testing.T, configData string) *httptest.Server {
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
			if strings.Contains(msg, "getConfigData") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(configData))
				return
			}
			_, _ = w.Write([]byte(`{"actions":[{"id":"123;a","state":"ERROR"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func configDataWithCustom() string {
	return `{"actions":[{"id":"123;a","state":"SUCCESS","returnValue":{"apiNamesToKeyPrefixes":` +
		`{"User":"005","Account":"001","Contact":"003","Broker__c":"a0X","Property__c":"a0Y"}}}]}`
}

func TestObjectExposureFiresOnCustomObjects(t *testing.T) {
	srv := auraServer(t, configDataWithCustom())
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 object-exposure finding, got %d: %+v", len(results), results)
	}
	if results[0].Info.Severity != severity.Medium {
		t.Fatalf("expected Medium severity, got %v", results[0].Info.Severity)
	}
}

func TestObjectExposureNoCustomObjectsNoFire(t *testing.T) {
	// Only standard objects → not reported (crisp custom-object gate).
	standardOnly := `{"actions":[{"id":"123;a","state":"SUCCESS","returnValue":{"apiNamesToKeyPrefixes":{"User":"005","Account":"001"}}}]}`
	srv := auraServer(t, standardOnly)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("standard-only objects must not fire, got %+v", results)
	}
}

func TestObjectExposureSkipsNonSalesforce(t *testing.T) {
	// No Aura gateway → ConfirmSalesforce fails → no probing.
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
