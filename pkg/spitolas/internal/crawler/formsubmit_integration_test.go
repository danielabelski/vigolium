//go:build integration

package crawler

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

// jsDrivenPostFormIndex reproduces the GinJuiceShop stock-check pattern: a POST form
// whose submit is intercepted by JS that posts an application/xml body built from the
// form fields (the endpoint that carries XXE / body+cookie SQLi), plus a second POST
// form with NO JS handler (exercised by the synthesized-fetch fallback).
const jsDrivenPostFormIndex = `<!doctype html><html><head><title>shop</title></head><body>
<h1>Product</h1>
<form id="stockCheckForm" action="/stock" method="POST">
  <input type="hidden" name="productId" value="1">
  <select name="storeId"><option value="7">Store 7</option></select>
  <button type="submit">Check stock</button>
</form>
<form id="plainForm" action="/plain" method="POST">
  <input type="text" name="q" value="x">
  <button type="submit">Go</button>
</form>
<script>
window.contentType = 'application/xml';
function payload(data){
  var xml = '<?xml version="1.0"?><stockCheck>';
  for (var p of data.entries()) { xml += '<' + p[0] + '>' + p[1] + '</' + p[0] + '>'; }
  return xml + '</stockCheck>';
}
document.getElementById('stockCheckForm').addEventListener('submit', function(e){
  e.preventDefault();
  fetch(this.getAttribute('action'), {
    method: this.getAttribute('method'),
    headers: { 'Content-Type': window.contentType },
    body: payload(new FormData(this))
  });
});
</script>
</body></html>`

// TestSubmitPostFormsReachesJSDrivenEndpoint verifies the deterministic POST-form
// submission recovers a JS-driven endpoint (application/xml stock check) that the
// GET-form path and the opportunistic interaction crawl both miss, and that the
// plain (no-handler) POST form is covered by the synthesized-fetch fallback.
func TestSubmitPostFormsReachesJSDrivenEndpoint(t *testing.T) {
	var stockHits, plainHits int32
	var gotXML atomic.Bool
	var gotProductID atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, jsDrivenPostFormIndex)
	})
	mux.HandleFunc("/stock", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt32(&stockHits, 1)
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "xml") {
				gotXML.Store(true)
			}
			if strings.Contains(string(body), "<productId>1</productId>") {
				gotProductID.Store(true)
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "42")
	})
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt32(&plainHits, 1)
		}
		_, _ = io.WriteString(w, "ok")
	})

	server := testutil.NewTestServerWithHandler(mux)
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 3
	cfg.MaxDepth = 2
	cfg.MaxDuration = 45 * time.Second

	crawler, err := New(cfg)
	if err != nil {
		t.Fatalf("new crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err := crawler.Run(ctx); err != nil {
		t.Fatalf("crawl: %v", err)
	}

	if atomic.LoadInt32(&stockHits) == 0 {
		t.Fatalf("JS-driven POST form was never submitted: /stock got 0 POSTs")
	}
	if !gotXML.Load() {
		t.Errorf("/stock was hit but never with an XML content-type — the page's JS submit handler did not fire (XXE would stay unreachable)")
	}
	if !gotProductID.Load() {
		t.Errorf("/stock XML body did not carry the form's productId field")
	}
	if atomic.LoadInt32(&plainHits) == 0 {
		t.Errorf("plain (no-handler) POST form was never submitted: /plain got 0 POSTs (fallback fetch missing)")
	}
}
