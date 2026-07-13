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
# Env knobs:
#   VIGOLIUM_BIN   vigolium binary                    (default: vigolium on PATH)
#   MODE           autopilot_mode: enforced|shadow    (default: enforced)
#   MODEL          olium model id                      (default: gpt-5.4)
#   MAX_DURATION   wall-clock cost ceiling            (default: 15m)
#   BROWSER        1 = enable agent-browser           (default: 1)
#   TARGET/CREDS/INSTRUCTION   override the profile defaults
#   CREDS          login as "user/pass" (fed to --credentials AND the prompt)
#   SESSION_DIR    pin debug artifacts here           (--session-dir)
#   TRANSCRIPT     copy transcript.jsonl here after   (--transcript)
#   AUTH_REQUIRED  1 = force auth/session preflight    (--auth-required)
#   SOURCE         source tree for login discovery     (--source)
#   SKIP_APP       1 = never start/stop the local app
#   NO_CONFIRM     1 = skip the cost confirmation
set -euo pipefail

VIGOLIUM_BIN="${VIGOLIUM_BIN:-vigolium}"
PROFILE="${PROFILE:-access-lab}"
MODE="${MODE:-enforced}"
MODEL="${MODEL:-gpt-5.4}"
MAX_DURATION="${MAX_DURATION:-15m}"
BROWSER="${BROWSER:-1}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$ROOT/test/testdata/vulnerable-apps/access-lab"
OUT_DIR="$(mktemp -d)"
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

PROVIDER="$(sed -n '/^ *olium:/,/^[^ ]/p' "$HOME/.vigolium/vigolium-configs.yaml" 2>/dev/null | grep -m1 'provider:' | awk '{print $2}')"
[ -n "$PROVIDER" ] || PROVIDER="(agent.olium.provider from config)"

# ---- build the exact command (printed == run) ----
CMD=( "$VIGOLIUM_BIN" agent autopilot
  --input "$TARGET"
  --model "$MODEL"
  --max-duration "$MAX_DURATION"
  --instruction "$INSTRUCTION"
  --json )
[ "$BROWSER" = "1" ] && CMD+=( --browser )
[ -n "${CREDS:-}" ] && CMD+=( --credentials "$CREDS" )
[ "${AUTH_REQUIRED:-}" = "1" ] && CMD+=( --auth-required )
[ -n "${SOURCE:-}" ] && CMD+=( --source "$SOURCE" )
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
printf "  browser       : %s\n" "$([ "$BROWSER" = "1" ] && echo 'enabled (agent-browser)' || echo disabled)"

printf "%s==================== COMMAND (raw) ====================%s\n" "$C_HDR" "$C_RST"
printf "%s" "$C_CMD"; printf '%q ' "${CMD[@]}"; printf "%s\n" "$C_RST"

printf "%s==================== INPUT (what the agent receives) ====================%s\n" "$C_HDR" "$C_RST"
printf "  --input       : %s%s%s\n" "$C_IN" "$TARGET" "$C_RST"
[ -n "${CREDS:-}" ] && printf "  --credentials : %s%s%s\n" "$C_IN" "$CREDS" "$C_RST"
printf "  --instruction :\n"
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

echo "==> running autopilot (see the COMMAND block above) ..."
SUMMARY_JSON="$OUT_DIR/summary.json"
set +e
"${CMD[@]}" >"$SUMMARY_JSON"
RUN_RC=$?
set -e
echo "==> autopilot exit: $RUN_RC"

UUID="$(grep -oE '"agentic_scan_uuid"[: ]+"[^"]+"' "$SUMMARY_JSON" | head -1 | grep -oE '[0-9a-fA-F-]{36}' || true)"
echo "==> agentic_scan_uuid: ${UUID:-<none>}"

FINDINGS_JSON="$OUT_DIR/findings.json"
if [ -n "$UUID" ]; then
  "$VIGOLIUM_BIN" finding -j --agentic-scan "$UUID" >"$FINDINGS_JSON" 2>/dev/null || echo '{}' >"$FINDINGS_JSON"
else
  "$VIGOLIUM_BIN" finding -j >"$FINDINGS_JSON" 2>/dev/null || echo '{}' >"$FINDINGS_JSON"
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
  "$VIGOLIUM_BIN" finding --agentic-scan "${UUID:-none}" 2>/dev/null | head -40 || true
fi

echo ""
echo "Full triage:   $VIGOLIUM_BIN finding --agentic-scan ${UUID:-<uuid>} --with-records"
echo "Summary JSON:  $SUMMARY_JSON"
echo "Findings JSON: $FINDINGS_JSON"
