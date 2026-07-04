package aem_xxe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

const aemLoginBody = `<html><head><title>AEM Sign In</title></head><body>Adobe Experience Manager</body></html>`
const guidePath = "/libs/fd/af/components/guideContainer.af.internalsubmit.json"

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	rest := s[i+len(a):]
	j := strings.Index(rest, b)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// xxeServer models the Forms guideContainer. expand=true parses+expands the
// internal entity (vulnerable); expand=false echoes the payload verbatim (safe).
func xxeServer(t *testing.T, expand bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/libs/granite/core/content/login.html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(aemLoginBody))
			return
		}
		if r.URL.Path == guidePath {
			w.Header().Set("Content-Type", "application/json")
			xml := prefillXML(r)
			if expand {
				// AEM parses the JSON, then the XML, expanding the internal entity.
				mk := between(xml, `<!ENTITY vigent "`, `"`)
				_, _ = w.Write([]byte(`{"data":"<afData>` + mk + `<afBoundData/></afData>"}`))
				return
			}
			// Safe parser: reflect the raw XML (still contains &xxe;).
			b, _ := json.Marshal(map[string]string{"echo": xml})
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// prefillXML mirrors AEM: parse the guideState form value as JSON and return the
// guidePrefillXml field (the real XML, with JSON escaping resolved).
func prefillXML(r *http.Request) string {
	_ = r.ParseForm()
	var gs struct {
		GuideState struct {
			GuideContext struct {
				GuidePrefillXML string `json:"guidePrefillXml"`
			} `json:"guideContext"`
		} `json:"guideState"`
	}
	_ = json.Unmarshal([]byte(r.Form.Get("guideState")), &gs)
	return gs.GuideState.GuideContext.GuidePrefillXML
}

func TestXXEEntityExpansionConfirmed(t *testing.T) {
	srv := xxeServer(t, true)
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	found := false
	for _, res := range results {
		if strings.Contains(res.Info.Name, "XXE") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected XXE entity-expansion finding, got %+v", results)
	}
}

func TestXXEEchoNotConfirmed(t *testing.T) {
	srv := xxeServer(t, false) // echoes &xxe; verbatim → not expansion
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL)

	results, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("payload echo (unexpanded &xxe;) must not confirm XXE, got %+v", results)
	}
}

func TestXXESkipsNonAEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == guidePath {
			mk := between(prefillXML(r), `<!ENTITY vigent "`, `"`)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":"<afData>` + mk + `</afData>"}`))
			return
		}
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
		t.Fatalf("non-AEM target must yield no findings, got %+v", results)
	}
}
