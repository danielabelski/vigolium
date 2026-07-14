//go:build ignore

// generate.go regenerates the sample transcripts in this directory using the
// *real* sessionlog recorder (pkg/olium/sessionlog) that vigolium uses in
// production, so the fixtures can never drift from the writer's actual output.
//
// Regenerate from the repo root with:
//
//	go run ./test/testdata/agent-transcripts/generate.go
//
// It writes two fixtures next to this file:
//
//	autopilot-transcript.jsonl          — a single-section run (login → IDOR → report)
//	autopilot-durable-transcript.jsonl  — a durable, multi-section run that mines
//	                                      prior traffic (query_records), rotates a
//	                                      section, hits a tool error + an engine error
//
// Event ids and timestamps are non-deterministic by design — the recorder mints
// them from crypto/rand and wall-clock time — so a regenerated file differs
// line-for-line while staying schema-identical. See README.md for the schema.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

func main() {
	dir := sourceDir()
	// A single explicit arg keeps the historical behavior (write the canonical
	// fixture to that path); no arg writes both fixtures to their default names.
	if len(os.Args) > 1 {
		writeAutopilot(os.Args[1])
		return
	}
	writeAutopilot(filepath.Join(dir, "autopilot-transcript.jsonl"))
	writeDurable(filepath.Join(dir, "autopilot-durable-transcript.jsonl"))
}

// writeAutopilot emits a single-section run: login → prove a horizontal IDOR →
// report it → probe a write (blocked) → summarize.
func writeAutopilot(out string) {
	rec := mustNew(out, sessionlog.Meta{
		SessionID:     "8f2c1a90-4e6d-4b2a-9c3e-1d5a7b0e9f42",
		Provider:      "openai-codex-oauth",
		Model:         "gpt-5.4",
		ThinkingLevel: "medium",
		Cwd:           "/home/tester/targets/access-lab",
	})

	rec.SectionStart("sec-01", 1, "operator", "Log in as wiener and hunt IDOR/BOLA on /api/users/{id}")

	rec.UserPrompt(`This is an AUTHORIZED test of a shop I own (http://127.0.0.1:9899).
Credentials: username "wiener" password "peter" (low-privilege user, id 1); a victim "carlos" (id 2) exists.
Log in via POST /login, then find and PROVE horizontal IDOR on GET /api/users/{id} (read carlos's data).
Report the confirmed issue with the exact request(s) and the response evidence.`)

	// Turn 1: think, narrate, log in.
	think(rec, "I'll authenticate as wiener first ", "to capture a session cookie, then walk the user id space.")
	text(rec, "Logging in as wiener to obtain a session cookie.")
	turnToolUse(rec, &stream.Usage{Input: 1840, Output: 96, CacheRead: 1536, TotalTokens: 1936, Cost: 0.0042},
		stream.ToolCall{ID: "call_login", Name: "http_request", Arguments: map[string]any{
			"method": "POST", "url": "http://127.0.0.1:9899/login",
			"headers": map[string]any{"Content-Type": "application/json"},
			"body":    `{"username":"wiener","password":"peter"}`,
		}})
	toolOK(rec, "call_login", "http_request",
		"HTTP/1.1 200 OK\r\nSet-Cookie: session=eyJ1aWQiOjEsInVzZXIiOiJ3aWVuZXIifQ; Path=/; HttpOnly\r\nContent-Type: application/json\r\n\r\n{\"ok\":true,\"id\":1,\"user\":\"wiener\"}")

	// Turn 2: think, request the victim's record with the same cookie.
	think(rec, "Baseline is my own record (id=1); now request id=2 with the same cookie. ", "If id=2 returns carlos's data, that's a horizontal IDOR.")
	turnToolUse(rec, &stream.Usage{Input: 2210, Output: 74, CacheRead: 1792, TotalTokens: 2284, Cost: 0.0051},
		stream.ToolCall{ID: "call_idor", Name: "http_request", Arguments: map[string]any{
			"method": "GET", "url": "http://127.0.0.1:9899/api/users/2",
			"headers": map[string]any{"Cookie": "session=eyJ1aWQiOjEsInVzZXIiOiJ3aWVuZXIifQ"},
		}})
	toolOK(rec, "call_idor", "http_request",
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":2,\"user\":\"carlos\",\"email\":\"carlos@access-lab.test\",\"role\":\"user\",\"credits\":500}")

	// Turn 3: record the finding via the report tool.
	text(rec, "Confirmed: wiener's session reads carlos's full record via GET /api/users/2. Recording the finding.")
	turnToolUse(rec, &stream.Usage{Input: 2480, Output: 132, CacheRead: 2048, TotalTokens: 2612, Cost: 0.0068},
		stream.ToolCall{ID: "call_report", Name: "report_finding", Arguments: map[string]any{
			"title": "Horizontal IDOR/BOLA on GET /api/users/{id}", "severity": "high", "confidence": "firm",
			"url":      "http://127.0.0.1:9899/api/users/2",
			"evidence": "wiener (id=1) session returned carlos (id=2) record incl. email carlos@access-lab.test and credits=500",
		}})
	toolOK(rec, "call_report", "report_finding",
		"finding recorded: id=fnd_7c21 severity=high title=\"Horizontal IDOR/BOLA on GET /api/users/{id}\"")

	// Turn 4: an errored tool result, to show isError fidelity.
	text(rec, "Checking whether /api/users/2 also allows a write (PATCH).")
	turnToolUse(rec, &stream.Usage{Input: 2600, Output: 60, CacheRead: 2048, TotalTokens: 2660, Cost: 0.0055},
		stream.ToolCall{ID: "call_patch", Name: "http_request", Arguments: map[string]any{
			"method": "PATCH", "url": "http://127.0.0.1:9899/api/users/2", "body": `{"credits":9999}`,
		}})
	toolErr(rec, "call_patch", "http_request", "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\n\r\nmethod not allowed")

	// Final assistant summary turn (text only, stops).
	text(rec, "Done. One confirmed High: horizontal IDOR on GET /api/users/{id} — a low-priv user reads any user's record. The PATCH write is blocked (405).")
	turnStop(rec, &stream.Usage{Input: 2720, Output: 88, CacheRead: 2048, TotalTokens: 2808, Cost: 0.0061})

	rec.SectionEnd("sec-01", "completed", "task_complete",
		"Proved horizontal IDOR on GET /api/users/{id}; PATCH write blocked (405). 1 High finding recorded.", 48213)
	closeRec(rec, out)
}

// writeDurable emits a durable, multi-section run: it mines prior Burp/scan
// traffic already in the project DB (query_records), proves an IDOR, rotates the
// section on the context budget, then hits a tool error and a terminal engine
// error before finishing. Exercises: multi-line thinking, section rotation, an
// isError tool result, and a standalone `error` event.
func writeDurable(out string) {
	rec := mustNew(out, sessionlog.Meta{
		SessionID:     "b41d7e02-9a3c-4f18-8e5b-2c6f0a9d1e77",
		Provider:      "anthropic-oauth",
		Model:         "claude-opus-4-8",
		ThinkingLevel: "high",
		Cwd:           "/home/tester/targets/shop",
	})

	// --- Section 1: mine prior traffic, confirm an IDOR candidate, then rotate.
	rec.SectionStart("sec-a", 1, "operator", "Mine the prior Burp traffic in the DB, then hunt IDOR")
	rec.UserPrompt(`Prior Burp/proxy traffic for https://shop.test is already imported into the project DB.
Mine it first with query_records (don't re-crawl from scratch), then confirm any IDOR/BOLA you can.`)

	// Multi-line thinking (paragraph + list) to exercise thinking rendering.
	think(rec,
		"There's prior traffic in the DB, so I should not re-crawl. Plan:\n",
		"1. query_records to see the captured endpoints (source=burp).\n",
		"2. Pick object-id endpoints (/api/orders/{id}, /api/users/{id}).\n",
		"3. Replay one across a different user's id to test BOLA.")
	text(rec, "Reviewing the prior traffic already captured in the project DB before sending anything new.")
	turnToolUse(rec, &stream.Usage{Input: 3120, Output: 88, CacheRead: 2560, TotalTokens: 3208, Cost: 0.0071},
		stream.ToolCall{ID: "call_q1", Name: "query_records", Arguments: map[string]any{
			"source": "burp", "limit": 25,
		}})
	toolOK(rec, "call_q1", "query_records",
		"25 records (source=burp):\n"+
			"  GET  https://shop.test/api/orders/1012  200  application/json\n"+
			"  GET  https://shop.test/api/orders/1013  200  application/json\n"+
			"  GET  https://shop.test/api/users/42     200  application/json\n"+
			"  POST https://shop.test/api/login        200  application/json\n"+
			"  … 21 more — filter with method/path/status")

	think(rec, "The Burp capture shows /api/orders/{id} accessed as user 42. ",
		"I'll replay order 1012 (another user's order) with user 42's session to test cross-user read.")
	turnToolUse(rec, &stream.Usage{Input: 3480, Output: 70, CacheRead: 2816, TotalTokens: 3550, Cost: 0.0079},
		stream.ToolCall{ID: "call_replay", Name: "replay_request", Arguments: map[string]any{
			"uuid": "rec-burp-1012", "set_headers": map[string]any{"Cookie": "session=u42"},
		}})
	toolOK(rec, "call_replay", "replay_request",
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"order\":1012,\"owner\":\"alice\",\"total\":248.5,\"card_last4\":\"4242\"}")

	text(rec, "User 42 read alice's order 1012 (card_last4 leaked). That's a BOLA. Recording it.")
	turnToolUse(rec, &stream.Usage{Input: 3760, Output: 120, CacheRead: 3072, TotalTokens: 3880, Cost: 0.0091},
		stream.ToolCall{ID: "call_rep", Name: "report_finding", Arguments: map[string]any{
			"title": "BOLA on GET /api/orders/{id}", "severity": "high", "confidence": "firm",
			"url":      "https://shop.test/api/orders/1012",
			"evidence": "session u42 read order 1012 owned by alice; response leaked card_last4=4242",
		}})
	toolOK(rec, "call_rep", "report_finding",
		"finding recorded: id=fnd_a19c severity=high title=\"BOLA on GET /api/orders/{id}\"")

	rec.SectionEnd("sec-a", "rotated", "context_budget",
		"Confirmed BOLA on /api/orders/{id} from prior traffic; rotating to widen the id sweep.", 61840)

	// --- Section 2: reconstructed brief, a tool error, then a terminal error.
	rec.SectionStart("sec-b", 2, "operator", "Sweep more order ids; verify the BOLA generalizes")
	think(rec, "Continuing from the reconstructed brief: BOLA is confirmed on 1012. ",
		"I'll sweep a few more ids to show it isn't a one-off, then stop.")
	turnToolUse(rec, &stream.Usage{Input: 2050, Output: 54, CacheRead: 1600, TotalTokens: 2104, Cost: 0.0048},
		stream.ToolCall{ID: "call_sweep", Name: "http_request", Arguments: map[string]any{
			"method": "GET", "url": "https://shop.test/api/orders/1013",
			"headers": map[string]any{"Cookie": "session=u42"},
		}})
	// Tool error: the target rate-limited the sweep.
	toolErr(rec, "call_sweep", "http_request", "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 30\r\n\r\nrate limited")

	// A terminal engine error (provider stream failure) — a standalone `error` line.
	rec.Record(engine.Event{Type: engine.EventError, Err: "provider stream error: 429 rate limited by upstream after 3 retries"})

	text(rec, "Halting: the target is rate-limiting and the provider stream errored. One confirmed High (BOLA) recorded from the prior traffic.")
	turnStop(rec, &stream.Usage{Input: 2210, Output: 96, CacheRead: 1600, TotalTokens: 2306, Cost: 0.0053})

	rec.SectionEnd("sec-b", "completed", "halt", "Rate-limited mid-sweep; 1 confirmed BOLA reported.", 22110)
	closeRec(rec, out)
}

// --- tiny helpers over the recorder so the scenarios stay readable ---

func mustNew(out string, meta sessionlog.Meta) *sessionlog.Recorder {
	// sessionlog.New opens O_APPEND, so a leftover fixture would accumulate a
	// second session tree on every run. Remove it first so each regeneration
	// starts from a clean, single-session file.
	if err := os.Remove(out); err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	rec, err := sessionlog.New(out, meta)
	if err != nil {
		panic(err)
	}
	return rec
}

func think(rec *sessionlog.Recorder, deltas ...string) {
	for _, d := range deltas {
		rec.Record(engine.Event{Type: engine.EventThinkingDelta, Delta: d})
	}
}

func text(rec *sessionlog.Recorder, s string) {
	rec.Record(engine.Event{Type: engine.EventTextDelta, Delta: s})
}

func turnToolUse(rec *sessionlog.Recorder, usage *stream.Usage, calls ...stream.ToolCall) {
	rec.Record(engine.Event{Type: engine.EventTurnDone, StopReason: stream.StopReasonToolUse, Usage: usage, ToolCalls: calls})
}

func turnStop(rec *sessionlog.Recorder, usage *stream.Usage) {
	rec.Record(engine.Event{Type: engine.EventTurnDone, StopReason: stream.StopReasonStop, Usage: usage})
}

func toolOK(rec *sessionlog.Recorder, id, name, result string) {
	rec.Record(engine.Event{Type: engine.EventToolExecEnd, ToolCallID: id, ToolName: name, ToolResult: result})
}

func toolErr(rec *sessionlog.Recorder, id, name, result string) {
	rec.Record(engine.Event{Type: engine.EventToolExecEnd, ToolCallID: id, ToolName: name, ToolResult: result, ToolIsErr: true})
}

func closeRec(rec *sessionlog.Recorder, out string) {
	if err := rec.Close(); err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", out)
}

// sourceDir resolves the directory of this source file, independent of the
// caller's working directory.
func sourceDir() string {
	_, self, _, _ := runtime.Caller(0)
	return filepath.Dir(self)
}
