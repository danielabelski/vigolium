#!/usr/bin/env bash
# smoke-autopilot.sh — durable-autopilot SMOKE test against a vulnerable target.
#
# Runs the REAL vigolium agent autopilot (a live, PAID, non-deterministic LLM
# run): it logs in with credentials and hunts the auth / access-control /
# injection bugs a native, unauthenticated scan can't reach. NOT a deterministic
# e2e test — it costs money.
#
# Pick a target with PROFILE (or set TARGET/CREDS/INSTRUCTION explicitly):
#   PROFILE=access-lab   (default) local hermetic lab, scored 7/7      :9899
#   PROFILE=ginandjuice  live PortSwigger demo (carlos/hunter2)        external
#   PROFILE=crapi        local OWASP crAPI (needs `make crapi-up`)      :8888
#   PROFILE=juiceshop    local OWASP Juice Shop (needs juiceshop-up)    :3000
#
# The run is STATELESS by default: autopilot writes into a throwaway SQLite DB
# under a temp dir (your real ~/.vigolium DB is never touched) and the follow-up
# finding queries read that same DB via `-S --db`. It also always emits the raw
# Pi-compatible transcript.jsonl and validates its format after the run.
#
# Env knobs:
#   VIGOLIUM_BIN   vigolium binary                    (default: vigolium on PATH)
#   MODE           autopilot_mode: enforced|shadow    (default: enforced)
#   MODEL          olium model id                      (default: gpt-5.4)
#   MAX_DURATION   wall-clock cost ceiling            (default: 15m)
#   STATELESS      1 = throwaway --db, main DB untouched (default: 1; 0 = real DB)
#   SEED_PRIOR     1 = seed the DB with a native scan first, then run autopilot
#                  --no-prescan --prior-context auto to mine that prior traffic
#                  (simulates --burp-bridge-url / a Burp import). Needs STATELESS=1.
#   TARGET/CREDS/INSTRUCTION   override the profile defaults
#   CREDS          login as "user/pass" (woven into the prompt; autopilot extracts
#                  credentials + auth intent from the prompt — there is no --credentials flag)
#   SESSION_DIR    pin debug artifacts here           (--session-dir)
#   TRANSCRIPT     raw transcript.jsonl copy path     (--transcript; default: temp dir)
#   SOURCE         source tree for login discovery     (--source)
#   SKIP_APP       1 = never start/stop the local app
#   NO_CONFIRM     1 = skip the cost confirmation
set -euo pipefail

VIGOLIUM_BIN="${VIGOLIUM_BIN:-vigolium}"
PROFILE="${PROFILE:-access-lab}"
MODE="${MODE:-enforced}"
MODEL="${MODEL:-gpt-5.4}"
MAX_DURATION="${MAX_DURATION:-15m}"
STATELESS="${STATELESS:-1}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"  # test/smoke-test/ -> repo root
APP_DIR="$ROOT/test/testdata/vulnerable-apps/access-lab"
OUT_DIR="$(mktemp -d)"
# Raw transcript always lands here (overridable); stateless run uses a throwaway DB.
TRANSCRIPT="${TRANSCRIPT:-$OUT_DIR/transcript.jsonl}"
if [ "$STATELESS" = "1" ]; then SCAN_DB="$OUT_DIR/scan.sqlite"; else SCAN_DB=""; fi
SEED_PRIOR="${SEED_PRIOR:-0}"
if [ "$SEED_PRIOR" = "1" ] && [ -z "$SCAN_DB" ]; then
  echo "SEED_PRIOR=1 needs a throwaway DB — set STATELESS=1 (default)"; exit 2
fi
APP_PID=""
MANAGE_APP=0   # 1 = this script starts/stops a local go-run app (access-lab only)
SCORE=0        # 1 = run the access-lab ground-truth scorecard

# ---- colors (auto-off when not a TTY or NO_COLOR is set) ----
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_HDR=$'\033[1;33m'; C_CMD=$'\033[1;36m'; C_IN=$'\033[0;32m'; C_RST=$'\033[0m'
else
  C_HDR=''; C_CMD=''; C_IN=''; C_RST=''
fi

# ---- profile → TARGET / CREDS / INSTRUCTION ----
case "$PROFILE" in
  access-lab)
    TARGET="${TARGET:-http://127.0.0.1:9899}"
    CREDS="${CREDS:-wiener/peter}"
    MANAGE_APP=1; SCORE=1
    read -r -d '' DEFAULT_INSTRUCTION <<'EOF' || true
This is an AUTHORIZED test of a deliberately vulnerable shop that I own.
Credentials: username "wiener" password "peter" (a normal, low-privilege user, id 1); a victim account "carlos" (id 2) and an "admin" account also exist.
Log in as wiener via POST /login (JSON {"username","password"}; sets a `session` cookie), then find and PROVE:
  1. Horizontal IDOR/BOLA on GET /api/users/{id} and GET /api/orders/{id} (read carlos's/admin's data).
  2. Vertical broken access control on GET /admin/dashboard and POST /admin/promote.
  3. Mass assignment on PATCH /api/me (set your own credits/role).
  4. DOM-based XSS on GET /welcome (confirm real browser execution).
  5. Stored XSS: POST /api/reviews then GET /product (confirm real browser execution).
Report each confirmed issue with the exact request(s) and the response/execution evidence.
EOF
    ;;
  ginandjuice)
    TARGET="${TARGET:-https://ginandjuice.shop}"
    CREDS="${CREDS:-carlos/hunter2}"
    ;;
  crapi)
    TARGET="${TARGET:-http://127.0.0.1:8888}"
    CREDS="${CREDS:-}"
    PROFILE_HINT="crAPI is an API-heavy shop. Focus on BOLA/IDOR over vehicle, order, and mechanic objects (numeric/UUID ids), mass assignment on profile/vehicle updates, and broken function-level authorization (mechanic/admin-only endpoints reachable as a normal user). The API is under /identity, /workshop, /community."
    ;;
  juiceshop)
    TARGET="${TARGET:-http://127.0.0.1:3000}"
    CREDS="${CREDS:-}"
    PROFILE_HINT="OWASP Juice Shop. Focus on basket/order IDOR (change the basket id), the admin section reachable by a normal user, broken access control on /api and /rest endpoints, and reflected/DOM XSS in product search. Confirm XSS with real browser execution."
    ;;
  *)
    echo "unknown PROFILE '$PROFILE' (access-lab|ginandjuice|crapi|juiceshop)"; exit 2;;
esac

# Generic instruction for the non-access-lab profiles (parameterized by target+creds).
if [ "$PROFILE" != "access-lab" ]; then
  CRED_USER="${CREDS%%/*}"; CRED_PASS="${CREDS#*/}"
  read -r -d '' DEFAULT_INSTRUCTION <<EOF || true
This is an AUTHORIZED security test of ${TARGET} that I am permitted to test.
Log in with username "${CRED_USER}" password "${CRED_PASS}" (register/create the session if needed), hold the authenticated
session, then hunt for high-impact bugs a normal user must not be able to trigger: broken access control / IDOR / BOLA
(read or act on OTHER users' objects), privilege escalation, mass assignment, authentication bypass, and reflected/stored/
DOM XSS (confirm REAL browser execution, not just reflection).
${PROFILE_HINT:-}
For each confirmed issue, report a finding with the exact request(s) and the response/execution evidence that proves it.
Prefer depth over breadth; stop when you have solid, reproduced findings.
EOF
fi
INSTRUCTION="${INSTRUCTION:-$DEFAULT_INSTRUCTION}"

cleanup() {
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null || true
  if [ "$MANAGE_APP" = "1" ] && [ "${SKIP_APP:-}" != "1" ]; then
    local lp; lp=$(lsof -ti tcp:9899 2>/dev/null || true)
    [ -n "$lp" ] && kill $lp 2>/dev/null || true
  fi
}
trap cleanup EXIT

# validate_transcript checks that the emitted transcript.jsonl matches the
# Pi-compatible olium schema (see test/testdata/agent-transcripts/README.md):
# valid JSONL, a `session`/`model_change`/`thinking_level_change` header trio,
# session version 3, a linear parentId chain, and at least one assistant +
# toolResult message. Prefers python3 (full checks), falls back to jq, then a
# minimal grep. Returns non-zero on a malformed transcript.
validate_transcript() {
  local path="$1"
  if [ ! -s "$path" ]; then
    echo "  transcript not written or empty: $path"
    return 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$path" <<'PY'
import json, sys
recs, errs = [], []
with open(sys.argv[1], encoding="utf-8") as fh:
    lines = [l for l in fh.read().splitlines() if l.strip()]
if not lines:
    print("  empty transcript"); sys.exit(1)
for i, l in enumerate(lines, 1):
    try:
        recs.append(json.loads(l))
    except Exception as e:
        errs.append(f"line {i}: invalid JSON: {e}")
if [r.get("type") for r in recs[:3]] != ["session", "model_change", "thinking_level_change"]:
    errs.append(f"header trio = {[r.get('type') for r in recs[:3]]}, want session/model_change/thinking_level_change")
if recs and recs[0].get("version") != 3:
    errs.append(f"session version = {recs[0].get('version')}, want 3")
if recs and "parentId" in recs[0]:
    errs.append("session line must not carry parentId")
prev = None
for i, r in enumerate(recs, 1):
    if r.get("type") == "session":
        prev = None
        continue
    if "parentId" not in r:
        errs.append(f"line {i} ({r.get('type')}): missing parentId"); continue
    pid = r["parentId"]
    if prev is None and pid is not None:
        errs.append(f"line {i} ({r.get('type')}): parentId={pid!r}, want null (chain head)")
    elif prev is not None and pid != prev:
        errs.append(f"line {i} ({r.get('type')}): parentId={pid!r}, want {prev!r} (broken chain)")
    prev = r.get("id")
roles = {(r.get("message") or {}).get("role") for r in recs if r.get("type") == "message"}
for want in ("assistant", "toolResult"):
    if want not in roles:
        errs.append(f"no {want} message present")
if errs:
    print("\n".join("  - " + e for e in errs)); sys.exit(1)
print(f"  {len(lines)} lines, header trio + version 3, linear parentId chain, roles={sorted(r for r in roles if r)}")
PY
    return $?
  elif command -v jq >/dev/null 2>&1; then
    if ! jq -e . "$path" >/dev/null 2>&1; then
      echo "  invalid JSONL (jq parse failed)"; return 1
    fi
    local first; first="$(head -1 "$path" | jq -r '"\(.type) v\(.version)"' 2>/dev/null)"
    [ "$first" = "session v3" ] || { echo "  first line = '$first', want 'session v3'"; return 1; }
    echo "  $(grep -c . "$path") lines, valid JSONL, session header v3 (jq check; install python3 for full checks)"
    return 0
  else
    if grep -q '"type":"session"' "$path" && grep -q '"version":3' "$path"; then
      echo "  session header present ($(grep -c . "$path") lines; install python3/jq for full checks)"
      return 0
    fi
    echo "  session header missing"; return 1
  fi
}

PROVIDER="$(sed -n '/^ *olium:/,/^[^ ]/p' "$HOME/.vigolium/vigolium-configs.yaml" 2>/dev/null | grep -m1 'provider:' | awk '{print $2}')"
[ -n "$PROVIDER" ] || PROVIDER="(agent.olium.provider from config)"

# ---- build the exact command (printed == run) ----
CMD=( "$VIGOLIUM_BIN" agent autopilot
  --input "$TARGET"
  --model "$MODEL"
  --max-duration "$MAX_DURATION"
  --prompt "$INSTRUCTION"
  --json )
# Browser is always on for autopilot; credentials + auth intent are taken from
# the prompt (the instruction below already contains the login + credentials).
[ -n "${SOURCE:-}" ] && CMD+=( --source "$SOURCE" )
[ -n "${SCAN_DB:-}" ] && CMD+=( --db "$SCAN_DB" )
# SEED_PRIOR: skip the fresh pre-scan and instead front-load the traffic the seed
# scan already put in the DB — this is what mining Burp-bridge traffic looks like.
[ "$SEED_PRIOR" = "1" ] && CMD+=( --no-prescan --prior-context auto )
[ -n "${SESSION_DIR:-}" ] && CMD+=( --session-dir "$SESSION_DIR" )
[ -n "${TRANSCRIPT:-}" ] && CMD+=( --transcript "$TRANSCRIPT" )

printf "%s==================== SETUP ====================%s\n" "$C_HDR" "$C_RST"
printf "  profile       : %s\n" "$PROFILE"
printf "  binary        : %s\n" "$VIGOLIUM_BIN"
printf "  provider      : %s\n" "$PROVIDER"
printf "  model         : %s   (override MODEL=...)\n" "$MODEL"
printf "  autopilot_mode: %s\n" "$MODE"
printf "  target        : %s\n" "$TARGET"
printf "  max-duration  : %s   (cost ceiling; override MAX_DURATION=...)\n" "$MAX_DURATION"
printf "  browser       : %s\n" "always on (agent-browser)"
printf "  stateless db  : %s\n" "$([ -n "$SCAN_DB" ] && echo "$SCAN_DB (throwaway; main DB untouched)" || echo 'off (writes to your real DB)')"
printf "  seed prior    : %s\n" "$([ "$SEED_PRIOR" = "1" ] && echo 'on — seed a scan, then autopilot --no-prescan --prior-context auto (simulates --burp-bridge-url)' || echo off)"
printf "  transcript    : %s\n" "$TRANSCRIPT"

printf "%s==================== COMMAND (raw) ====================%s\n" "$C_HDR" "$C_RST"
printf "%s" "$C_CMD"; printf '%q ' "${CMD[@]}"; printf "%s\n" "$C_RST"

printf "%s==================== INPUT (what the agent receives) ====================%s\n" "$C_HDR" "$C_RST"
printf "  --input       : %s%s%s\n" "$C_IN" "$TARGET" "$C_RST"
[ -n "${CREDS:-}" ] && printf "  credentials   : %s%s%s   (in the prompt below; autopilot extracts them)\n" "$C_IN" "$CREDS" "$C_RST"
printf "  --prompt      :\n"
printf '%s\n' "$INSTRUCTION" | sed "s/^/    ${C_IN}/;s/\$/${C_RST}/"
printf "%s=======================================================================%s\n\n" "$C_HDR" "$C_RST"

echo "  !!! This starts a REAL, billable LLM autopilot run under your"
echo "  !!! agent.olium provider credentials. Ctrl-C now to abort."
if [ "${NO_CONFIRM:-}" != "1" ]; then
  read -r -p "  Proceed? [y/N] " ans || ans=""
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "aborted."; exit 1; }
fi

"$VIGOLIUM_BIN" config set agent.olium.autopilot_mode "$MODE" >/dev/null
echo "==> set agent.olium.autopilot_mode = $MODE (persists in your config)"

if [ "$MANAGE_APP" = "1" ] && [ "${SKIP_APP:-}" != "1" ]; then
  echo "==> starting access-lab (go run) ..."
  ( cd "$APP_DIR" && ACCESS_LAB_ADDR=":9899" go run . ) &
  APP_PID=$!
  for _ in $(seq 1 30); do curl -sf "$TARGET/" >/dev/null 2>&1 && break; sleep 1; done
fi

# SEED_PRIOR: populate the throwaway DB with a native scan BEFORE autopilot, so
# the run has prior traffic to mine (standing in for a --burp-bridge-url import;
# the DB-population outcome is identical). Best-effort — a partial scan still
# leaves traffic the prior-context brief can surface.
if [ "$SEED_PRIOR" = "1" ]; then
  echo "==> seeding prior traffic into $SCAN_DB (simulates a --burp-bridge-url import) ..."
  "$VIGOLIUM_BIN" scan -t "$TARGET" --db "$SCAN_DB" \
    --only discovery,spidering,dynamic-assessment --scanning-max-duration 3m >/dev/null 2>&1 \
    || echo "  (seed scan returned non-zero — continuing; the DB may still hold partial traffic)"
  echo "==> seed done — the record count is reported by the 'Prior context:' line below"
fi

echo "==> running autopilot (see the COMMAND block above) ..."
SUMMARY_JSON="$OUT_DIR/summary.json"
STDERR_LOG="$OUT_DIR/autopilot-stderr.log"
set +e
# Tee stderr (the --json live stream + our progress lines) to a log so we can
# assert on it after the run, while still showing it live.
"${CMD[@]}" >"$SUMMARY_JSON" 2> >(tee "$STDERR_LOG" >&2)
RUN_RC=$?
set -e
echo "==> autopilot exit: $RUN_RC"

UUID="$(grep -oE '"agentic_scan_uuid"[: ]+"[^"]+"' "$SUMMARY_JSON" | head -1 | grep -oE '[0-9a-fA-F-]{36}' || true)"
echo "==> agentic_scan_uuid: ${UUID:-<none>}"

# Validate the raw transcript format (the whole point of --transcript here).
echo ""
printf "%s==================== TRANSCRIPT ====================%s\n" "$C_HDR" "$C_RST"
echo "==> raw transcript: $TRANSCRIPT"
if validate_transcript "$TRANSCRIPT"; then
  TRANSCRIPT_OK=1
  echo "  FORMAT OK  (Pi-compatible olium transcript)"
else
  TRANSCRIPT_OK=0
  echo "  FORMAT FAIL  (see errors above)"
fi
printf "%s===================================================%s\n" "$C_HDR" "$C_RST"

# SEED_PRIOR: assert autopilot front-loaded the seeded traffic (the "Prior
# context:" line prints when the brief fires) and that the fresh pre-scan was
# skipped (--no-prescan). This is the observable proof the --burp-bridge-url /
# prior-context path worked end-to-end.
if [ "$SEED_PRIOR" = "1" ]; then
  echo ""
  printf "%s==================== PRIOR CONTEXT ====================%s\n" "$C_HDR" "$C_RST"
  if grep -q "Prior context:" "$STDERR_LOG" 2>/dev/null; then
    PRIOR_OK=1
    grep -m1 "Prior context:" "$STDERR_LOG" | sed 's/^[[:space:]]*/  /'
    echo "  PRIOR-CONTEXT OK  (autopilot mined the seeded traffic instead of starting cold)"
  else
    PRIOR_OK=0
    echo "  PRIOR-CONTEXT FAIL  (no 'Prior context:' line — the brief did not fire)"
  fi
  if grep -q "Pre-scan:" "$STDERR_LOG" 2>/dev/null; then
    echo "  NOTE: a fresh pre-scan ran despite --no-prescan (unexpected)"
  else
    echo "  pre-scan skipped (--no-prescan)"
  fi
  printf "%s======================================================%s\n" "$C_HDR" "$C_RST"
fi

# Findings read from the throwaway DB under -S when stateless (main DB untouched).
FIND_DB=()
[ -n "${SCAN_DB:-}" ] && FIND_DB=( -S --db "$SCAN_DB" )
FINDINGS_JSON="$OUT_DIR/findings.json"
if [ -n "$UUID" ]; then
  "$VIGOLIUM_BIN" finding -j ${FIND_DB[@]+"${FIND_DB[@]}"} --agentic-scan "$UUID" >"$FINDINGS_JSON" 2>/dev/null || echo '{}' >"$FINDINGS_JSON"
else
  "$VIGOLIUM_BIN" finding -j ${FIND_DB[@]+"${FIND_DB[@]}"} >"$FINDINGS_JSON" 2>/dev/null || echo '{}' >"$FINDINGS_JSON"
fi

if [ "$SCORE" = "1" ]; then
  echo ""
  printf "%s==================== SCORECARD ====================%s\n" "$C_HDR" "$C_RST"
  echo "  (enforced mode promotes only verifier-confirmed candidates to findings)"
  score() { if grep -iqE "$2" "$FINDINGS_JSON"; then echo "  CATCH  $1"; else echo "  MISS   $1"; fi; }
  score "V1/V2 IDOR / BOLA (cross-user object access)"  'idor|bola|/api/users/|/api/orders/|home delivery code|carlos@access'
  score "V3/V4 broken access control (admin / privesc)" 'FLAG\{broken-access-control|/admin/dashboard|/admin/promote|vertical|privilege escalat'
  score "V5 DOM-based XSS (browser-only)"                'dom.?based|dom xss|/welcome|location\.(search|hash)'
  score "V6 stored XSS (multi-step + browser)"           'stored xss|/api/reviews|/product|innerhtml'
  score "V7 mass assignment (multi-step logic)"          'mass.?assign|/api/me|credits|\bpatch\b'
  printf "%s==================================================%s\n" "$C_HDR" "$C_RST"
else
  echo ""
  echo "==> findings for this run:"
  "$VIGOLIUM_BIN" finding ${FIND_DB[@]+"${FIND_DB[@]}"} --agentic-scan "${UUID:-none}" 2>/dev/null | head -40 || true
fi

echo ""
echo "Full triage:   $VIGOLIUM_BIN finding ${FIND_DB[@]+"${FIND_DB[@]}"} --agentic-scan ${UUID:-<uuid>} --with-records"
echo "Summary JSON:  $SUMMARY_JSON"
echo "Findings JSON: $FINDINGS_JSON"
echo "Transcript:    $TRANSCRIPT   (rendered replay: $VIGOLIUM_BIN log ${UUID:-<uuid>})"

# Surface a malformed transcript as a non-zero exit even when the run itself
# succeeded — the format is a contract other tools parse against.
if [ "${TRANSCRIPT_OK:-1}" != "1" ]; then
  echo "==> transcript FORMAT check FAILED"
  exit 1
fi

# Under SEED_PRIOR, the prior-context brief firing is the whole point — fail if
# it didn't.
if [ "$SEED_PRIOR" = "1" ] && [ "${PRIOR_OK:-1}" != "1" ]; then
  echo "==> prior-context check FAILED (autopilot did not front-load the seeded traffic)"
  exit 1
fi
