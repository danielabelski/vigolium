package mcp_tool_fuzz

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

// callArg extracts params.arguments[arg] from a tools/call body.
func callArg(body []byte, arg string) string {
	var env struct {
		Params struct {
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &env)
	if v, ok := env.Params.Arguments[arg].(string); ok {
		return v
	}
	return ""
}

const passwdContent = "root:x:0:0:root:/root:/bin/bash"

// vulnToolHandler exposes a "readfile" tool with a string `path` argument and
// returns /etc/passwd content when the path looks like a traversal payload.
func vulnToolHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"readfile","description":"reads a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}}`)
		case "tools/call":
			path := callArg(raw, "path")
			text := "ok: " + path
			if strings.Contains(path, "passwd") || strings.Contains(path, "..") {
				text = passwdContent // unrestricted read => LFI
			}
			out := map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": text}},
					"isError": false,
				},
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// safeToolHandler exposes the same tool but never honours a traversal payload,
// the secure behaviour.
func safeToolHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"readfile","description":"reads a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}}`)
		case "tools/call":
			path := callArg(raw, "path")
			if strings.Contains(path, "passwd") || strings.Contains(path, "..") || strings.HasPrefix(path, "file://") {
				out := map[string]any{
					"jsonrpc": "2.0", "id": 1,
					"result": map[string]any{
						"content": []map[string]any{{"type": "text", "text": "access denied"}},
						"isError": true,
					},
				}
				b, _ := json.Marshal(out)
				_, _ = w.Write(b)
				return
			}
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsToolLFI flags a tool whose argument leaks /etc/passwd
// via a path-traversal payload.
func TestScanPerHost_DetectsToolLFI(t *testing.T) {
	srv := httptest.NewServer(vulnToolHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a tool leaking /etc/passwd must be flagged")
	assert.Equal(t, "MCP Tool Argument Local File Inclusion", res[0].Info.Name)
	assert.Equal(t, "path", res[0].FuzzingParameter)
}

// TestScanPerHost_SafeServerNoFinding ensures a tool that rejects traversal
// payloads yields nothing.
func TestScanPerHost_SafeServerNoFinding(t *testing.T) {
	srv := httptest.NewServer(safeToolHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a tool rejecting traversal payloads must not be flagged")
}

// noisyToolHandler honours the traversal read but returns a benign error string
// that merely CONTAINS the old bare markers (`/bin/`, `:0:0:`) without any real
// passwd entry — exactly what the former substring matcher flagged as LFI.
func noisyToolHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"readfile","description":"reads a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}}`)
		case "tools/call":
			out := map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": "sh: /bin/loader failed at offset :0:0: — no such file"}},
					"isError": true,
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
// false positive: a tool response that merely contains `/bin/` and `:0:0:`
// substrings (an error string) — not a real passwd entry — must not be flagged.
func TestScanPerHost_NoFalsePositiveOnNoise(t *testing.T) {
	srv := httptest.NewServer(noisyToolHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "scattered /bin/ and :0:0: substrings without a real passwd entry must not be flagged")
}

// sqliToolHandler exposes a "search" tool whose `q` argument is concatenated
// into a SQL query: a quote in the value produces a MySQL syntax error.
func sqliToolHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search","description":"search records","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}]}}`)
		case "tools/call":
			val := callArg(raw, "q")
			text := "ok: 0 rows"
			if strings.ContainsAny(val, "'\"") {
				text = "you have an error in your SQL syntax; check the manual near '" + val + "'"
			}
			out := map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": text}},
					"isError": false,
				},
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsToolSQLi flags a tool argument that surfaces a DBMS
// error on a quote payload (error-based SQLi), while the benign baseline does not.
func TestScanPerHost_DetectsToolSQLi(t *testing.T) {
	srv := httptest.NewServer(sqliToolHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a DBMS error surfaced by a quote payload must be flagged")
	assert.Equal(t, "MCP Tool Argument SQL Injection", res[0].Info.Name)
	assert.Equal(t, "q", res[0].FuzzingParameter)
}

// TestConfirmSQLError checks the differential contract: an error present in the
// baseline (a server that always prints a DB banner) must NOT confirm.
func TestConfirmSQLError(t *testing.T) {
	ok, _ := confirmSQLError("you have an error in your SQL syntax near 'x'", "ok: 0 rows")
	assert.True(t, ok, "DB error absent from baseline should confirm")

	ok, _ = confirmSQLError("you have an error in your SQL syntax", "startup: you have an error in your SQL syntax")
	assert.False(t, ok, "DB error also present in baseline must not confirm")

	ok, _ = confirmSQLError("echoed back: vigolium'\"", "ok")
	assert.False(t, ok, "a mere reflection of the payload must not confirm")
}

// numericSQLiToolHandler exposes a "lookup" tool with an INTEGER `id` argument
// that surfaces a DBMS error when the value carries a quote (numeric-context SQLi).
func numericSQLiToolHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"lookup","description":"lookup by id","inputSchema":{"type":"object","properties":{"id":{"type":"integer"}}}}]}}`)
		case "tools/call":
			val := callArg(raw, "id")
			text := "ok: row"
			if strings.ContainsAny(val, "'\"") {
				text = "ORA-01756: quoted string not properly terminated"
			}
			out := map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": false},
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsNumericSQLi verifies error-based SQLi is fuzzed on
// integer arguments, not only strings.
func TestScanPerHost_DetectsNumericSQLi(t *testing.T) {
	srv := httptest.NewServer(numericSQLiToolHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a DBMS error on a numeric arg quote payload must be flagged")
	assert.Equal(t, "MCP Tool Argument SQL Injection", res[0].Info.Name)
	assert.Equal(t, "id", res[0].FuzzingParameter)
}

// echoToolHandler reflects the `msg` argument verbatim in its response — the
// reflective prompt-injection sink.
func echoToolHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echoes input","inputSchema":{"type":"object","properties":{"msg":{"type":"string"}}}}]}}`)
		case "tools/call":
			msg := callArg(raw, "msg")
			out := map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{"content": []map[string]any{{"type": "text", "text": "you said: " + msg}}, "isError": false},
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsPromptReflection is the regression for the sentinel
// marker fix: an argument reflected verbatim is flagged as a prompt-injection
// sink (previously the check regenerated a fresh random marker that never matched).
func TestScanPerHost_DetectsPromptReflection(t *testing.T) {
	srv := httptest.NewServer(echoToolHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	found := false
	for _, e := range res {
		if e.Info.Name == "MCP Tool Argument Prompt Injection" {
			found = true
		}
	}
	assert.True(t, found, "a reflected sentinel must be flagged as a prompt-injection sink")
}

// TestStringArgs keeps only string-typed (or untyped) argument names.
func TestStringArgs(t *testing.T) {
	args := map[string]any{"path": "x", "count": 1, "flag": true}
	types := map[string]string{"path": "string", "count": "integer", "flag": "boolean"}
	got := stringArgs(args, types)
	assert.Equal(t, []string{"path"}, got)
}

// TestCapitalise covers the vuln-tag label helper.
func TestCapitalise(t *testing.T) {
	assert.Equal(t, "Command Injection", capitalise("rce"))
	assert.Equal(t, "Local File Inclusion", capitalise("lfi"))
	assert.Equal(t, "SSRF", capitalise("ssrf"))
	assert.Equal(t, "SQL Injection", capitalise("sqli"))
	assert.Equal(t, "", capitalise(""))
}

// TestCanProcess_RequiresResponse verifies the detection gate.
func TestCanProcess_RequiresResponse(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/mcp")
	assert.False(t, New().CanProcess(rr))
	assert.False(t, New().CanProcess(nil))
}
