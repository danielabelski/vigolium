package mcp_origin_rebinding

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

// vulnOriginHandler accepts the initialize handshake regardless of the Origin
// header (no rebinding protection).
func vulnOriginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if rpcMethod(raw) == "initialize" {
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

// strictOriginHandler rejects any request carrying a foreign Origin header,
// the secure DNS-rebinding defence.
func strictOriginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !strings.HasPrefix(origin, "http://127.0.0.1") && !strings.HasPrefix(origin, "http://localhost") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if rpcMethod(raw) == "initialize" {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

// TestScanPerHost_DetectsMissingOriginValidation flags a server that initializes
// despite a foreign Origin header.
func TestScanPerHost_DetectsMissingOriginValidation(t *testing.T) {
	srv := httptest.NewServer(vulnOriginHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "initialize succeeding with a foreign Origin must be flagged")
	assert.Equal(t, "MCP Missing Origin Validation (DNS Rebinding Sink)", res[0].Info.Name)
}

// TestScanPerHost_StrictOriginNoFinding ensures a server that rejects foreign
// Origins yields no finding.
func TestScanPerHost_StrictOriginNoFinding(t *testing.T) {
	srv := httptest.NewServer(strictOriginHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server enforcing Origin validation must not be flagged")
}

// TestIsRebindingRelevantHost locks in the locality gate that decides whether a
// missing-Origin-validation finding is a High DNS-rebinding sink (local/private)
// or a low-severity note (public).
func TestIsRebindingRelevantHost(t *testing.T) {
	local := []string{
		"127.0.0.1", "127.0.0.1:8080", "localhost", "localhost:3000",
		"[::1]:9000", "10.0.0.5", "192.168.1.10:8000", "172.16.0.1",
		"169.254.1.1", "app.local", "0.0.0.0:8080",
	}
	for _, h := range local {
		assert.True(t, isRebindingRelevantHost(h), "%s should be treated as rebinding-relevant", h)
	}
	remote := []string{"example.com", "api.example.com:443", "8.8.8.8", "203.0.113.5:8080"}
	for _, h := range remote {
		assert.False(t, isRebindingRelevantHost(h), "%s should NOT be treated as rebinding-relevant", h)
	}
}

// TestCanProcess_RequiresResponse verifies the detection gate.
func TestCanProcess_RequiresResponse(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/mcp")
	assert.False(t, New().CanProcess(rr))
	assert.False(t, New().CanProcess(nil))
}
