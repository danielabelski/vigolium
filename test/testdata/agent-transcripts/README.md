# Agent session transcripts (`transcript.jsonl`)

These are **sample olium session transcripts** — the Pi-compatible, append-only
conversation log every olium engine run emits (olium TUI, headless `-p`,
autopilot, swarm, query). They are here so external tools can learn the format
from real, schema-faithful examples without having to run a paid agent:

| File | What it exercises |
|------|-------------------|
| `autopilot-transcript.jsonl` | A single-section run: login → prove IDOR → `report_finding` → a blocked write (`isError` tool result) → summarize. `thinking` + `text` + `toolCall` parts, one `section_start`/`section_end`. |
| `autopilot-durable-transcript.jsonl` | A durable, **multi-section** run that mines prior traffic (`query_records`, `replay_request`), rotates a section (`section_end` status `rotated`), then hits a tool error **and** a terminal engine `error` event. Includes **multi-line `thinking`** blocks. |

They are written by `pkg/olium/sessionlog` (the production writer) and read by
`vigolium log <uuid>` (rendered replay) / `vigolium log <uuid> --raw` (verbatim
JSONL). Both were produced by the real recorder via
`test/testdata/agent-transcripts/generate.go` — regenerate with:

```bash
go run ./test/testdata/agent-transcripts/generate.go
```

Event ids (8 hex chars) and timestamps come from `crypto/rand` + wall clock, so a
regenerated file differs line-for-line while staying schema-identical. The
`thinking` parts (the model's reasoning) are captured in the transcript and
rendered as muted `⋈ thinking` blocks by `vigolium log`.

## Format

One JSON object per line (JSONL). Every line has a `type`. The file is an
event **tree** chained by `parentId`:

- The first line is the standalone `session` header — it carries **no**
  `parentId`.
- The next chained node (`model_change`) has `"parentId": null` (chain head);
  every later line's `parentId` is the `id` of the line before it. Operator
  sections are strictly serial, so the chain is linear.
- Unknown `type`s must be **ignored** by readers (forward-compatible): the
  `error`, `section_start`, `section_end`, and `section_interrupted` events are
  vigolium additions on top of the base Pi schema — a Pi viewer skips them.

### Line types

| `type`                  | Meaning                                                                 |
|-------------------------|-------------------------------------------------------------------------|
| `session`               | Header. `version` (3), `id` (session UUID), `timestamp`, `cwd`. No `parentId`. |
| `model_change`          | `provider`, `modelId`. First chained node → `parentId: null`.           |
| `thinking_level_change` | `thinkingLevel` (`low`/`medium`/`high`).                                 |
| `message`               | A `user` / `assistant` / `toolResult` message; body is under `message`. |
| `section_start`         | Durable-autopilot bounded section opens. `sectionId`, `seq`, `kind`, `task`. |
| `section_end`           | Section closes. `sectionId`, `status`, `rotationReason`, `summary`, `durationMs`. |
| `section_interrupted`   | Section was interrupted (e.g. run resumed after a crash). `sectionId`.  |
| `error`                 | Terminal engine error. `error` (string).                                |

### `message` bodies

The `message` object's `role` selects the shape:

- **`user`** — `{ role, content[], timestamp }`. `content` is text parts.
- **`assistant`** — `{ role, content[], provider, model, usage, stopReason, timestamp }`.
  `content` mixes ordered parts: `thinking` (`{type,thinking}`), `text`
  (`{type,text}`), and `toolCall` (`{type, id, name, arguments}` — arguments are
  the **full** tool call args). `stopReason` is `toolUse` or `stop`. One
  assistant message == one model turn (thinking/text deltas are coalesced).
- **`toolResult`** — `{ role, toolCallId, toolName, content[], isError, timestamp }`.
  `toolCallId` links back to the assistant `toolCall.id`. `content` is text
  parts holding the **full, untruncated** tool output. `isError` marks a failed
  tool call.

`usage` is `{ input, output, cacheRead, cacheWrite, totalTokens, cost{...} }`.
Envelope `timestamp`s are ISO-8601 millis (`2026-07-13T16:58:33.198Z`); the
per-message `timestamp` inside a body is epoch millis.

## Fidelity caveat

Structurally Pi-compatible and readable, but provider-opaque **resume** fields
(per-message signatures, the per-component cost split, `responseId`) are omitted.
The log is for reading and debugging, not for replaying back into Pi.
