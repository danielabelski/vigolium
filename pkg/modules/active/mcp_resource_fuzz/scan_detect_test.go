package mcp_resource_fuzz

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func rpcMethod(body []byte) string {
	var env struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Method
}

// readURI extracts params.uri from a resources/read body.
func readURI(body []byte) string {
	var env struct {
		Params struct {
			URI string `json:"uri"`
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Params.URI
}

const passwdContent = "root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"

// vulnResourceHandler exposes one resource and serves whatever file:// or
// traversal URI is requested via resources/read (path traversal / LFI).
func vulnResourceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "resources/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"result":{"resources":[{"uri":"file:///app/readme.txt","name":"readme"}]}}`)
		case "resources/templates/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":4,"result":{"resourceTemplates":[]}}`)
		case "resources/read":
			uri := readURI(raw)
			text := "benign file contents"
			if strings.Contains(uri, "passwd") || strings.Contains(uri, "..") {
				text = passwdContent // unrestricted read => leak /etc/passwd
			}
			out := map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"contents": []map[string]any{{"uri": uri, "text": text}},
				},
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// safeResourceHandler exposes a resource but rejects any traversal/file URI,
// the secure behaviour.
func safeResourceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "resources/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"result":{"resources":[{"uri":"file:///app/readme.txt","name":"readme"}]}}`)
		case "resources/templates/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":4,"result":{"resourceTemplates":[]}}`)
		case "resources/read":
			uri := readURI(raw)
			if strings.Contains(uri, "passwd") || strings.Contains(uri, "..") || strings.HasPrefix(uri, "file://") {
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"resource not found"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"contents":[{"uri":"file:///app/readme.txt","text":"benign"}]}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsLFI flags an MCP resources/read that returns
// /etc/passwd content for a traversal payload.
func TestScanPerHost_DetectsLFI(t *testing.T) {
	srv := httptest.NewServer(vulnResourceHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "resources/read leaking /etc/passwd must be flagged")
	assert.Equal(t, "MCP Resource Read Local File Inclusion", res[0].Info.Name)
}

// TestScanPerHost_SafeServerNoFinding ensures a server that rejects traversal
// URIs yields nothing.
func TestScanPerHost_SafeServerNoFinding(t *testing.T) {
	srv := httptest.NewServer(safeResourceHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server rejecting traversal reads must not be flagged")
}

// noisyResourceHandler honours the traversal read but returns content that
// merely CONTAINS the old bare markers (`/bin/`, `:0:0:`) without any real
// passwd entry — exactly what the former substring matcher flagged as LFI.
func noisyResourceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "resources/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"result":{"resources":[{"uri":"file:///app/readme.txt","name":"readme"}]}}`)
		case "resources/templates/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":4,"result":{"resourceTemplates":[]}}`)
		case "resources/read":
			uri := readURI(raw)
			out := map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"contents": []map[string]any{{"uri": uri, "text": "loader error: /bin/ld returned :0:0: while linking"}},
				},
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_NoFalsePositiveOnNoise is the regression for the bare-marker
// false positive: a resources/read response that merely contains `/bin/` and
// `:0:0:` substrings — not a real passwd entry — must not be flagged.
func TestScanPerHost_NoFalsePositiveOnNoise(t *testing.T) {
	srv := httptest.NewServer(noisyResourceHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "scattered /bin/ and :0:0: substrings without a real passwd entry must not be flagged")
}

// oastStub is a minimal enabled OASTProvider so the OAST SSRF payload is built.
type oastStub struct{}

func (oastStub) GenerateURL(_, _, _, _, _ string) string { return "http://oast.example/cb" }
func (oastStub) RecordPayload(_, _ string)               {}
func (oastStub) Enabled() bool                           { return true }

// TestScanPerHost_OASTNoInBandFinding is the regression for the premature OAST
// finding: with the OAST provider enabled but no callback (a safe server), the
// module must NOT emit an in-band "check OAST log" finding. Confirmation is the
// global poller's job.
func TestScanPerHost_OASTNoInBandFinding(t *testing.T) {
	srv := httptest.NewServer(safeResourceHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{OASTProvider: oastStub{}})
	require.NoError(t, err)
	assert.Empty(t, res, "an OAST payload with no callback must not produce an in-band finding")
}

// metadataResourceHandler serves an AWS IMDS meta-data listing for the
// 169.254.169.254 URL (cloud-metadata SSRF), benign content otherwise.
func metadataResourceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "resources/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"result":{"resources":[{"uri":"file:///app/readme.txt","name":"readme"}]}}`)
		case "resources/templates/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":4,"result":{"resourceTemplates":[]}}`)
		case "resources/read":
			uri := readURI(raw)
			text := "benign file contents"
			if strings.Contains(uri, "169.254.169.254") {
				text = "ami-id\\nami-launch-index\\nhostname\\ninstance-id\\ninstance-type\\nlocal-ipv4\\niam/"
			}
			out := map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"contents": []map[string]any{{"uri": uri, "text": text}},
				},
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsCloudMetadataSSRF verifies the AWS-metadata payload
// (advertised in metadata, now implemented) confirms on a structural IMDS
// listing.
func TestScanPerHost_DetectsCloudMetadataSSRF(t *testing.T) {
	srv := httptest.NewServer(metadataResourceHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "an IMDS meta-data read must be flagged as SSRF")
	found := false
	for _, e := range res {
		if e.Info.Name == "MCP Resource Read SSRF" {
			found = true
		}
	}
	assert.True(t, found, "expected an SSRF finding for the cloud-metadata read")
}

// TestSubstituteTemplate covers the placeholder-substitution helper.
func TestSubstituteTemplate(t *testing.T) {
	phs := []string{"id", "fmt"}
	got := substituteTemplate("/x/{id}.{fmt}", phs, "id", "PAYLOAD")
	assert.Equal(t, "/x/PAYLOAD.1", got, "target placeholder gets the payload, others a benign filler")
}

// TestExtractPlaceholders covers the URI-template placeholder parser.
func TestExtractPlaceholders(t *testing.T) {
	assert.Nil(t, extractPlaceholders("/static"))
	assert.Equal(t, []string{"a", "b"}, extractPlaceholders("/{a}/{b}/{a}"))
}

// TestCanProcess_RequiresResponse verifies the detection gate.
func TestCanProcess_RequiresResponse(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/mcp")
	assert.False(t, New().CanProcess(rr))
	assert.False(t, New().CanProcess(nil))
}
