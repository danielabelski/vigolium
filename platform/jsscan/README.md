# jsscan

`jsscan` is Vigolium's bounded JavaScript intelligence engine. It extracts
source-aware HTTP templates, asset relationships, GraphQL operations,
WebSocket/SSE metadata, client routes, and browser security flows from modern
JavaScript and TypeScript bundles.

The helper uses protocol v2 by default. Results are typed, versioned, include
confidence and provenance, and keep large transformed documents in verified
artifacts instead of embedding them in JSON.

## Build and test

From the Vigolium repository root:

```bash
make ensure-jsscan       # rebuild the host helper only when its source hash changed
make update-jsscan       # build and stage every release target
```

From this directory:

```bash
bun install --linker isolated
bun run build:types
bun run test
bun run build:bin:host
```

`make ensure-jsscan` compares the current deterministic source fingerprint to
the fingerprint compiled into the staged helper. An old or protocol-incompatible
helper cannot silently run with newer Go code.

## Profiles

Each caller requests only the stages it consumes.

| Profile | Intended consumer | Main output |
|---|---|---|
| `endpoints` | endpoint-only API use | HTTP request facts |
| `dom-security` | passive DOM security module | DOM/browser flow facts |
| `beautify` | passive JS beautifier | beautified artifact only |
| `discovery` | normal content discovery | requests, assets, GraphQL, protocols, routes, optional transformed artifact |
| `discovery-lite` | larger discovery assets | discovery facts without transformed code |
| `full` | manual research | all analysis capabilities |
| `inspect` | debugging/evidence | full output plus request evidence |
| `legacy` | one-release compatibility | historical JSONL-compatible output |

Skipped stages appear with zero duration and `status: "skipped"` in stage
metrics. Webcrack is loaded lazily only when a beautify stage runs.

## CLI

```bash
# Typed v2 result envelope
jsscan --profile discovery --source-url https://app.test/assets/app.js app.js

# Put transformed/beautified documents in a contained artifact directory
jsscan --profile beautify --artifact-dir /tmp/jsscan-artifacts app.js

# Compatibility JSONL during migration
jsscan --protocol 1 --profile legacy app.js

# Machine-readable build and protocol contract
jsscan --capabilities

# Persistent length-prefixed worker transport (normally owned by Go)
jsscan --worker
```

Important limits include `--max-requests`, `--max-ast-nodes`,
`--max-output-bytes`, `--max-artifact-bytes`, and `--deadline-ms`.

## Protocol v2

`--capabilities` reports the protocol version, tool version, deterministic
source hash, supported profiles, record schema versions, runtime, framing, and
compiled dependency versions.

An `analysisResult` contains:

- `source`: source URL, content SHA-256, size, filename/media type, and bundle format.
- `stats`: overall status, record counts, total time, and per-stage metrics.
- `diagnostics`: explicit parse, budget, fallback, and artifact degradations.
- `records`: compact typed facts.
- `artifacts`: contained paths, hashes, lengths, and formats for large output.

Current typed records are:

- `httpRequest`: method, URL/query/body/header templates, client adapter,
  confidence, source span, and resolution evidence.
- `domFlow`: binding/order-aware source-to-sink browser flow.
- `assetReference`: dynamic/static chunks, workers, service workers, manifests,
  source maps, Wasm, and config assets.
- `graphqlOperation`: parsed operation/document, variables, persisted hash,
  endpoint, and transport.
- `websocket` and `eventSource`: protocol metadata and message/event behavior.
- `clientRoute`: framework-aware routes, guards, and lazy assets.
- `browserSecurityFlow`: postMessage trust, open redirect, script/network URL,
  dynamic execution, sensitive exfiltration, and prototype-pollution evidence.

Unknown future record kinds are retained by the Go decoder under a bounded
budget, allowing forward-compatible diagnostics instead of silent loss.

## Safety and degradation

- Per-analysis state is isolated; persistent workers process one framed job at
  a time and Go supplies bounded parallelism.
- Content/profile results are byte-bounded and coalesced by content hash.
- Worker admission is memory-weighted, with job-count and RSS recycling.
- Oversized discovery input first drops transformed-code work, then uses a
  bounded lexical endpoint/asset fallback. Hard-limit input is rejected.
- AST node, resolution, evidence, request, artifact, output, graph, and time
  budgets produce explicit diagnostics.
- Artifact paths are verified to remain inside the job directory before Go
  reads them; all job directories are removed after success, failure, or cancel.

## Vigolium integration policy

High-confidence request facts are eligible for exact replay with their observed
method, query, body, content type, and safe static headers. Medium-confidence
facts are available only in conservative mode. Low-confidence generic strings
are discovery hints and never cause direct traffic by default.

Relative requests resolve once against the JavaScript asset that produced them.
Authorization, cookies, API keys, CSRF tokens, browser-controlled headers, and
dynamic header values are not copied into replay traffic. Authentication comes
from Vigolium's configured session instead.

WebSocket and SSE facts never enter the ordinary HTTP variant generator. A
bounded handshake is synthesized only when `protocol_handshake: true` is set.

Source maps are fetched by Go under normal scope/auth/rate limits. Bounded
`sourcesContent` files are analyzed individually and stored as immutable,
session-scoped artifacts; source paths are display metadata and never filesystem
destinations.
