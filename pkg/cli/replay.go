package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/agent/input"
	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/replay"
	"github.com/vigolium/vigolium/pkg/replay/jar"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	replayRecordUUID     string
	replayFindingID      int64
	replayInput          string
	replayInputFile      string
	replayRawRequest     string
	replayRawRequestFile string
	replayHeaders        []string
	replayAuthSession    string
	replaySessionID      string
	replayNoCookies      bool
	replayNoRedirects    bool
	replayTargetURL      string
	replayTimeout        time.Duration
	replayInReplaceTop   bool
	replayOutputPath     string
	replayPretty         bool
	replayBurpBridgeURL  string
	replaySaveToBurp     bool
	replaySendViaBurp    bool
	replayHTTPMode       string
	replaySendTimeout    time.Duration
	replayToRepeater     bool
	replayRepeaterTab    string
	replayToOrganizer    bool
	replayNotes          string
	replayHighlight      string

	// Bulk-selection flags — when any is set (or a positional search term is
	// given), replay iterates the matching stored records instead of a single
	// source (mirrors `traffic --replay`, re-sending each record verbatim through
	// the diff engine). The filter surface tracks `vigolium traffic`. The
	// positional term is a local threaded through, not a flag global.
	replayAll             bool
	replayBulkHost        string
	replayBulkMethods     []string
	replayBulkStatus      []int
	replayBulkPath        string
	replayBulkSource      string
	replayBulkSearch      []string
	replayBulkBody        string
	replayBulkExclude     []string
	replayBulkExcludeBody string
	replayBulkFrom        string
	replayBulkTo          string
	replayBulkSort        string
	replayBulkAsc         bool
	replayBulkOffset      int
	replayBulkLimit       int
	replayConcurrency     int
)

var replayCmd = &cobra.Command{
	Use:   "replay [search-term]",
	Short: "Re-send a stored or supplied HTTP request and diff baseline vs replay",
	Args:  cobra.MaximumNArgs(1),
	Long: `Re-send an HTTP request — stored record, finding evidence, curl command, raw HTTP, ` +
		`Burp XML, base64, or URL — optionally overriding the raw request bytes, and emit a ` +
		`baseline-vs-replay diff (status, length, content-hash, timing).

For payload / insertion-point fuzzing (wordlists, --class, matchers, calibration),
use 'vigolium fuzz' — replay is for re-sending and confirming, not fuzzing.

The same engine that powers the autopilot's in-process replay_request tool. Use this
to drive vigolium externally (Claude Code, Cursor, Pi, CI scripts) — the JSON output
shape is stable so an agent can confirm a finding without parsing terminal output.

Cookies set by one replay persist to the next when --session-id is provided. Routes
through HTTP_PROXY / HTTPS_PROXY (or --proxy) for Burp-style inspection.

Burp bridge (needs --burp-bridge-url, the extension's loopback listener):
  --send-via-burp  send through Burp's own HTTP stack so exact bytes hit the wire —
                   the way to replay malformed/smuggling requests (pair with
                   --http-mode http1 so 'auto' doesn't negotiate HTTP/2 and reframe them)
  --to-repeater    also stage the request in a Burp Repeater tab for manual testing
  --to-organizer   also store the request + response in Burp's Organizer (--notes/--highlight)
  --save-to-burp  add the request + fresh response to Burp's Target Site map
None of these change the default send path — without them replay behaves exactly as before.

Bulk mode: pass a positional [search-term] (a broad fuzzy match, like
'vigolium traffic <term>'), --all, or any record filter to replay every matching
stored record instead of a single source. The selection surface mirrors
'vigolium traffic': --host/--method/--status/--path/--source, repeatable
--search (AND-combined), --body, --from/--to date range, --exclude-search/
--exclude-body, and --sort/--asc/--offset. Each matched record is re-sent
verbatim through the diff engine and results stream as JSONL (one object per
record). Throttle with -c/--concurrency and read a standalone export with -S --db.`,
	// Example is set in usage.go (replayExamples) so it renders colored like the
	// other commands via FormatExamples.
	RunE: runReplay,
}

func init() {
	rootCmd.AddCommand(replayCmd)
	f := replayCmd.Flags()

	// Source flags — exactly one of these resolves the baseline.
	f.StringVarP(&replayRecordUUID, "record-uuid", "u", "", "Stored HTTP record UUID to use as baseline")
	f.Int64Var(&replayFindingID, "finding-id", 0, "Finding ID — replay the finding's linked record (or its stored evidence)")
	f.StringVarP(&replayInput, "input", "i", "", "Raw input: curl, raw HTTP, Burp XML, base64, URL, or '-' for stdin")
	f.StringVar(&replayInputFile, "input-file", "", "Read --input value from a file")

	// Raw request override — send exact bytes verbatim (for payload/insertion-point
	// fuzzing use `vigolium fuzz` instead).
	f.StringVar(&replayRawRequest, "raw-request", "", "Full raw HTTP request override — send these exact bytes instead of the resolved baseline")
	f.StringVar(&replayRawRequestFile, "raw-request-file", "", "Read --raw-request from a file")

	// Header / auth merges.
	f.StringArrayVarP(&replayHeaders, "header", "H", nil, "Extra request header 'Name: value' (repeatable, overrides baseline)")
	f.StringVar(&replayAuthSession, "auth-session", "", "Auth session name to merge headers from (from 'vigolium auth list')")

	// Session / cookies.
	f.StringVar(&replaySessionID, "session-id", "",
		"Persist cookies across calls under ~/.vigolium/replay-jars/<id>.json")
	f.BoolVar(&replayNoCookies, "no-cookies", false, "Don't carry cookies (overrides --session-id)")

	// Network behaviour.
	f.BoolVar(&replayNoRedirects, "no-redirects", false, "Don't follow 30x redirects")
	f.StringVarP(&replayTargetURL, "target", "t", "", "Override scheme/host/port (e.g. https://staging.example.com)")
	f.DurationVar(&replayTimeout, "timeout", replay.DefaultTimeout, "Per-request timeout (e.g. 30s, 1m)")

	// Result handling.
	f.BoolVar(&replayInReplaceTop, "in-replace", false,
		"When the source is a stored record, update its stored response with the replay")
	f.StringVarP(&replayOutputPath, "output", "o", "", "Write JSON result to this file (default: stdout)")
	f.BoolVar(&replayPretty, "pretty", false, "Human-readable summary instead of JSON")
	f.StringVarP(
		&replayBurpBridgeURL,
		"burp-bridge-url",
		"B",
		burpbridge.URLFromEnvironment(),
		"Loopback Burp bridge URL used by --save-to-burp / --send-via-burp / --to-repeater / --to-organizer")
	f.BoolVar(
		&replaySaveToBurp,
		"save-to-burp",
		false,
		"Add each replayed request and its fresh response to Burp's Target Site map")
	f.BoolVar(&replaySendViaBurp, "send-via-burp", false,
		"Send the request through Burp's own HTTP stack (exact bytes — malformed/smuggling preserved) instead of Go's client; requires --burp-bridge-url")
	f.StringVar(&replayHTTPMode, "http-mode", "",
		"With --send-via-burp: wire protocol — auto|http1|http2|http2_ignore_alpn (default auto; use http1 for request smuggling/desync)")
	f.DurationVar(&replaySendTimeout, "send-timeout", 0,
		"With --send-via-burp: response timeout (<=2m; default uses the bridge's 30s)")
	f.BoolVar(&replayToRepeater, "to-repeater", false,
		"Stage the replayed request in a Burp Repeater tab for manual testing; requires --burp-bridge-url")
	f.StringVar(&replayRepeaterTab, "repeater-tab", "", "Repeater tab name for --to-repeater (default: vigolium)")
	f.BoolVar(&replayToOrganizer, "to-organizer", false,
		"Store the replayed request + response in Burp's Organizer for manual follow-up; requires --burp-bridge-url")
	f.StringVar(&replayNotes, "notes", "", "Note attached to the --to-organizer item (<=200 chars)")
	f.StringVar(&replayHighlight, "highlight", "",
		"Highlight colour for the --to-organizer item: none|red|orange|yellow|green|cyan|blue|pink|magenta|gray")

	// Bulk selection — mirror the traffic filters. Setting any of these (or
	// --all, or a positional search term) switches replay into bulk mode over
	// the matching stored records.
	f.BoolVarP(&replayAll, "all", "a", false, "Bulk: replay every matched stored record (lifts the -n/--limit cap); re-send all stored traffic")
	f.StringVar(&replayBulkHost, "host", "", "Bulk: filter records by hostname pattern (wildcard supported)")
	f.StringSliceVar(&replayBulkMethods, "method", nil, "Bulk: filter records by HTTP method (repeatable)")
	f.IntSliceVar(&replayBulkStatus, "status", nil, "Bulk: filter records by stored status code (repeatable)")
	f.StringVar(&replayBulkPath, "path", "", "Bulk: filter records by URL path pattern")
	f.StringVar(&replayBulkSource, "source", "", "Bulk: filter records by source (scanner, ingest-cli, ingest-proxy, seed, ...)")
	f.StringArrayVar(&replayBulkSearch, "search", nil, "Bulk: search across URL, path, and the raw request/response (headers + body); repeatable, AND-combined")
	f.StringVar(&replayBulkBody, "body", "", "Bulk: filter records whose request/response body contains this text")
	f.StringArrayVar(&replayBulkExclude, "exclude-search", nil, "Bulk: drop records where the term appears in the URL, path, or raw request/response (repeatable; dropped if ANY term matches — inverse of --search)")
	f.StringVar(&replayBulkExcludeBody, "exclude-body", "", "Bulk: drop records whose request/response body contains the term (inverse of --body)")
	f.StringVar(&replayBulkFrom, "from", "", "Bulk: only records after this date (YYYY-MM-DD or RFC3339)")
	f.StringVar(&replayBulkTo, "to", "", "Bulk: only records before this date (YYYY-MM-DD or RFC3339)")
	f.StringVar(&replayBulkSort, "sort", "created_at", "Bulk: sort matched records by: uuid, created_at, sent_at, method, status, time")
	f.BoolVar(&replayBulkAsc, "asc", false, "Bulk: sort ascending (default: descending)")
	f.IntVar(&replayBulkOffset, "offset", 0, "Bulk: skip this many matched records before replaying (pagination)")
	f.IntVarP(&replayBulkLimit, "limit", "n", 100, "Bulk: max records to replay (use --all to lift the cap)")
	f.IntVarP(&replayConcurrency, "concurrency", "c", 10, "Bulk: concurrent replays; keep low to avoid overwhelming an intercepting proxy like Burp")
	f.BoolVarP(&globalStateless, "stateless", "S", false, "Read records from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB")
}

func runReplay(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A positional argument is a broad fuzzy search term (like `traffic <term>`)
	// that selects records to replay in bulk. Kept as a local — not a flag
	// global — and threaded into the bulk path.
	var bulkFuzzy string
	if len(args) == 1 {
		bulkFuzzy = strings.TrimSpace(args[0])
	}
	// Any Burp write target needs the loopback bridge URL.
	needsBridge := replaySaveToBurp || replaySendViaBurp || replayToRepeater || replayToOrganizer
	if needsBridge && strings.TrimSpace(replayBurpBridgeURL) == "" {
		return fmt.Errorf("--save-to-burp/--send-via-burp/--to-repeater/--to-organizer require --burp-bridge-url")
	}
	httpMode, err := burpbridge.ParseHTTPMode(replayHTTPMode)
	if err != nil {
		return fmt.Errorf("--http-mode: %w", err)
	}
	if replayHTTPMode != "" && !replaySendViaBurp {
		fmt.Fprintf(os.Stderr, "%s --http-mode only applies with --send-via-burp; ignoring\n", terminal.WarningSymbol())
	}
	var bridgeClient *burpbridge.Client
	if replayBurpBridgeURL != "" {
		validated, verr := burpbridge.ValidateURL(replayBurpBridgeURL)
		if verr != nil {
			return fmt.Errorf("--burp-bridge-url: %w", verr)
		}
		replayBurpBridgeURL = validated
		bridgeClient, verr = burpbridge.New(validated)
		if verr != nil {
			return verr
		}
	}
	// Preflight the listener for the explicit send flags so an unavailable bridge
	// is a clear up-front error rather than one failure per record mid-run.
	if bridgeClient != nil && (replaySendViaBurp || replayToRepeater || replayToOrganizer) {
		info, herr := bridgeClient.Health(ctx)
		if herr != nil {
			return fmt.Errorf("burp bridge unavailable: %w", herr)
		}
		if info.InScopeOnly {
			fmt.Fprintf(os.Stderr, "%s Burp bridge is in-scope-only; out-of-scope targets will be refused (403)\n", terminal.WarningSymbol())
		}
	}

	rawOverride, err := loadReplayRawOverride()
	if err != nil {
		return err
	}

	pj, jarLoaded, jarErr := openReplayJar()
	if jarErr != nil {
		fmt.Fprintf(os.Stderr, "%s replay: cookie jar disabled (%v)\n", terminal.WarningSymbol(), jarErr)
	}
	rr := &replayRun{
		rawOverride: rawOverride,
		client:      newReplayClient(pj, replayTimeout),
		pj:          pj,
		jarLoaded:   jarLoaded,
		burpClient:  bridgeClient,
		saveToBurp:  replaySaveToBurp,
		sendViaBurp: replaySendViaBurp,
		toRepeater:  replayToRepeater,
		toOrganizer: replayToOrganizer,
		sendOpts: burpbridge.SendOptions{
			Mode:    httpMode,
			Timeout: replaySendTimeout,
		},
	}

	// Bulk mode: iterate every matching stored record through the same engine.
	if replayBulkRequested(bulkFuzzy) {
		return runReplayBulk(ctx, rr, bulkFuzzy)
	}

	src, err := resolveReplaySource(ctx)
	if err != nil {
		return err
	}

	overlay, err := buildReplayOverlay(ctx, src)
	if err != nil {
		return err
	}

	if replayTargetURL != "" {
		if err := applyTargetOverride(src, replayTargetURL); err != nil {
			return err
		}
	}

	out, err := rr.one(ctx, src, overlay)
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}

	saveReplayJar(pj)

	if replayPretty {
		return emitReplayPretty(out)
	}
	return emitReplayJSON(out)
}

// replayRun bundles the per-invocation replay settings that don't vary across
// records, so the single-source and bulk paths share one call shape instead of
// threading the same five values through every signature.
type replayRun struct {
	rawOverride []byte
	client      *http.Client
	pj          *jar.PersistentJar
	jarLoaded   int
	burpClient  *burpbridge.Client
	saveToBurp  bool
	sendViaBurp bool
	toRepeater  bool
	toOrganizer bool
	sendOpts    burpbridge.SendOptions
}

// newReplayClient builds the shared HTTP client for replay: the persistent
// cookie jar (when --session-id is set) plus --proxy routing, preserving the
// InsecureSkipVerify TLS config NewDefaultClient installs.
func newReplayClient(pj *jar.PersistentJar, timeout time.Duration) *http.Client {
	var jarForClient http.CookieJar
	if pj != nil {
		jarForClient = pj
	}
	client := replay.NewDefaultClient(jarForClient, timeout)
	if globalProxy != "" {
		if px, perr := url.Parse(globalProxy); perr == nil {
			if t, ok := client.Transport.(*http.Transport); ok {
				t.Proxy = http.ProxyURL(px)
			}
		}
	}
	return client
}

// saveReplayJar persists the cookie jar (no-op when --session-id is unset),
// warning to stderr on failure. Shared by the single-source and bulk paths.
func saveReplayJar(pj *jar.PersistentJar) {
	if pj == nil {
		return
	}
	if err := pj.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "%s replay: could not save cookie jar: %v\n", terminal.WarningSymbol(), err)
	}
}

// one runs a single source through the engine and returns the assembled
// output. Shared by single-source and bulk (per-record) replay. It honors
// --in-replace for stored records; the caller owns the cookie jar's lifecycle.
func (rr *replayRun) one(ctx context.Context, src *replaySource, overlay map[string]string) (*replayOutput, error) {
	opts := replay.Options{
		BaselineRequest:      src.BaselineRequest,
		BaselineResponse:     src.BaselineResponse,
		BaselineStatus:       src.BaselineStatus,
		BaselineResponseTime: src.BaselineResponseTime,
		RawRequest:           rr.rawOverride,
		Scheme:               src.Scheme,
		Hostname:             src.Hostname,
		Port:                 src.Port,
		HeaderOverlay:        overlay,
		NoRedirects:          replayNoRedirects,
		Client:               rr.client,
	}
	// --send-via-burp routes the actual send through Burp's engine so the exact bytes
	// (deliberate Content-Length, smuggling, unusual methods) reach the wire; the
	// baseline and diff logic are unchanged.
	if rr.sendViaBurp {
		opts.Sender = burpbridge.BridgeSender(rr.burpClient, src.Scheme, src.Hostname, src.Port, rr.sendOpts, replay.DefaultExcerptCap)
	}

	result, err := replay.Do(ctx, opts)
	if err != nil {
		return nil, err
	}

	if replayInReplaceTop {
		if err := persistReplayResponse(ctx, src, result); err != nil {
			fmt.Fprintf(os.Stderr, "%s replay: --in-replace failed: %v\n", terminal.WarningSymbol(), err)
		}
	}
	if rr.saveToBurp {
		if err := saveReplayResultToBurp(ctx, rr.burpClient, src, result); err != nil {
			return nil, fmt.Errorf("save replay to Burp: %w", err)
		}
	}
	if rr.toRepeater || rr.toOrganizer {
		if err := rr.stageReplayToBurp(ctx, src, result); err != nil {
			return nil, fmt.Errorf("stage replay to Burp: %w", err)
		}
	}

	out := buildReplayOutput(src, result, rr.jarLoaded, rr.pj)
	out.SavedToBurp = rr.saveToBurp
	out.SentViaBurp = rr.sendViaBurp
	out.StagedToRepeater = rr.toRepeater
	out.SavedToOrganizer = rr.toOrganizer
	return out, nil
}

// replaySource is the resolved baseline a replay diffs against. It can
// come from a stored record (with response), a finding (linked record OR
// inline evidence), or freshly-parsed input bytes (no stored response →
// the engine will synthesize a baseline by re-sending).
type replaySource struct {
	BaselineRequest      []byte
	BaselineResponse     []byte
	BaselineStatus       int
	BaselineResponseTime int64

	Scheme   string
	Hostname string
	Port     int

	RecordUUID  string
	FindingID   int64
	InputType   string
	OriginLabel string
}

func resolveReplaySource(ctx context.Context) (*replaySource, error) {
	set := 0
	if replayRecordUUID != "" {
		set++
	}
	if replayFindingID > 0 {
		set++
	}
	if replayInput != "" || replayInputFile != "" {
		set++
	}
	if set > 1 {
		return nil, fmt.Errorf("--record-uuid, --finding-id and --input/--input-file are mutually exclusive")
	}

	// openReadDB honors -S/--stateless: a standalone .sqlite/.jsonl export via
	// --db, project scoping off. Falls back to the project DB otherwise. Replay
	// re-sends the stored requests, so a --glob-db merge must keep the bodies.
	db, dbErr := openReadDB(globDBSkipSet{})
	var repo *database.Repository
	if dbErr == nil {
		repo = database.NewRepository(db)
	}

	switch {
	case replayRecordUUID != "":
		if repo == nil {
			return nil, fmt.Errorf("--record-uuid requires database access: %w", dbErr)
		}
		return sourceFromRecord(ctx, repo, replayRecordUUID)

	case replayFindingID > 0:
		if repo == nil {
			return nil, fmt.Errorf("--finding-id requires database access: %w", dbErr)
		}
		return sourceFromFinding(ctx, repo, replayFindingID)

	case replayInput != "" || replayInputFile != "":
		return sourceFromInput(ctx, repo, replayInput, replayInputFile)

	default:
		if data, ok := readStdinIfPiped(); ok {
			return sourceFromInputString(ctx, repo, data, "")
		}
		return nil, fmt.Errorf("no source specified: pass one of --record-uuid, --finding-id, --input, or pipe a request on stdin")
	}
}

func sourceFromRecord(ctx context.Context, repo *database.Repository, uuid string) (*replaySource, error) {
	rec, err := repo.GetRecordByUUID(ctx, uuid)
	if errors.Is(err, sql.ErrNoRows) || rec == nil {
		return nil, fmt.Errorf("no record with uuid %q", uuid)
	}
	if err != nil {
		return nil, fmt.Errorf("load record %q: %w", uuid, err)
	}
	if pid, _ := effectiveProjectUUID(); pid != "" && rec.ProjectUUID != pid {
		return nil, fmt.Errorf("record %q does not belong to the current project", uuid)
	}
	return sourceFromDBRecord(rec), nil
}

// sourceFromFinding resolves a finding to a baseline. Preference order:
//  1. First HTTPRecordUUIDs entry that loads — uses the canonical record
//     (which has correct host/port/scheme metadata).
//  2. Finding.Request / Finding.Response — for findings imported without
//     a backing HTTPRecord (audit findings, jsonl imports).
//
// We use the same priority order the UI does so the operator and the
// CLI see the same evidence.
func sourceFromFinding(ctx context.Context, repo *database.Repository, id int64) (*replaySource, error) {
	finding, err := repo.GetFindingByID(ctx, id)
	if err != nil || finding == nil {
		return nil, fmt.Errorf("load finding #%d: %w", id, err)
	}
	if pid, _ := effectiveProjectUUID(); pid != "" && finding.ProjectUUID != pid {
		return nil, fmt.Errorf("finding #%d does not belong to the current project", id)
	}

	for _, uuid := range finding.HTTPRecordUUIDs {
		rec, err := repo.GetRecordByUUID(ctx, uuid)
		if err == nil && rec != nil {
			src := sourceFromDBRecord(rec)
			src.FindingID = finding.ID
			src.OriginLabel = fmt.Sprintf("finding #%d via record %s", finding.ID, rec.UUID)
			return src, nil
		}
	}

	if finding.Request == "" {
		return nil, fmt.Errorf("finding #%d has no linked HTTPRecord and no inline request — can't replay", id)
	}
	src, err := sourceFromRawRequest([]byte(finding.Request), []byte(finding.Response), finding.URL)
	if err != nil {
		return nil, fmt.Errorf("finding #%d inline evidence: %w", id, err)
	}
	src.FindingID = finding.ID
	src.OriginLabel = fmt.Sprintf("finding #%d (inline evidence)", finding.ID)
	return src, nil
}

func sourceFromInput(ctx context.Context, repo *database.Repository, inline, file string) (*replaySource, error) {
	var data string
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read --input-file %q: %w", file, err)
		}
		data = string(b)
	case inline == "-":
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		data = string(b)
	default:
		data = inline
	}
	return sourceFromInputString(ctx, repo, data, file)
}

// sourceFromInputString delegates to the agent input normalizer so a
// curl/raw/burp string from an external driver parses the same way it
// would in autopilot.
func sourceFromInputString(ctx context.Context, repo *database.Repository, data, label string) (*replaySource, error) {
	if strings.TrimSpace(data) == "" {
		return nil, fmt.Errorf("input is empty")
	}
	records, err := input.NormalizeInput(ctx, data, "", repo)
	if err != nil {
		return nil, fmt.Errorf("normalize input: %w", err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no HTTP requests found in input")
	}
	rr := records[0]
	if rr.Request() == nil {
		return nil, fmt.Errorf("input did not yield a request")
	}
	rawReq := rr.Request().Raw()
	u, err := rr.URL()
	if err != nil || u == nil || u.URL == nil {
		return nil, fmt.Errorf("could not extract URL from input")
	}
	it := input.DetectInputType(data)
	src := &replaySource{
		BaselineRequest: rawReq,
		Scheme:          u.Scheme,
		Hostname:        u.Hostname(),
		Port:            portFromURL(u.URL),
		InputType:       string(it),
		OriginLabel:     fmt.Sprintf("input (%s)", it),
	}
	if rr.Response() != nil {
		raw := rr.Response().Raw()
		src.BaselineResponse = raw
		src.BaselineStatus = rr.Response().StatusCode()
	}
	if label != "" {
		src.OriginLabel = fmt.Sprintf("file %s", label)
	}
	return src, nil
}

func sourceFromRawRequest(rawReq, rawResp []byte, urlStr string) (*replaySource, error) {
	if len(rawReq) == 0 {
		return nil, fmt.Errorf("no raw request bytes")
	}
	if _, err := httpmsg.ParseRawRequestWithURL(string(rawReq), urlStr); err != nil {
		return nil, fmt.Errorf("parse raw request: %w", err)
	}
	u, err := url.Parse(urlStr)
	if err != nil || u == nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid URL %q on finding", urlStr)
	}
	return &replaySource{
		BaselineRequest:  rawReq,
		BaselineResponse: rawResp,
		Scheme:           u.Scheme,
		Hostname:         u.Hostname(),
		Port:             portFromURL(u),
	}, nil
}

// applyTargetOverride rewrites src's destination. The baseline request
// bytes (Host header, path) are left verbatim; only the socket we aim
// at changes — that's how an operator confirms a finding against a
// different env without re-deriving the request.
func applyTargetOverride(src *replaySource, target string) error {
	u, err := url.Parse(target)
	if err != nil || u == nil || u.Hostname() == "" {
		return fmt.Errorf("invalid --target %q: %w", target, err)
	}
	src.Scheme = u.Scheme
	src.Hostname = u.Hostname()
	src.Port = portFromURL(u)
	return nil
}

func portFromURL(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}

func loadReplayRawOverride() ([]byte, error) {
	switch {
	case replayRawRequest != "" && replayRawRequestFile != "":
		return nil, fmt.Errorf("--raw-request and --raw-request-file are mutually exclusive")
	case replayRawRequestFile != "":
		b, err := os.ReadFile(replayRawRequestFile)
		if err != nil {
			return nil, fmt.Errorf("read --raw-request-file %q: %w", replayRawRequestFile, err)
		}
		return b, nil
	case replayRawRequest != "":
		return []byte(replayRawRequest), nil
	}
	return nil, nil
}

// buildReplayOverlay: --auth-session headers are merged first, then
// --header K:V flags win last so an operator can override stored auth.
// Honors -S/--stateless (openReadDB/effectiveProjectUUID) so every DB touchpoint
// in the command reads from the same source.
func buildReplayOverlay(ctx context.Context, src *replaySource) (map[string]string, error) {
	overlay := map[string]string{}

	if replayAuthSession != "" {
		db, err := openReadDB(globDBSkipSet{})
		if err != nil {
			return nil, fmt.Errorf("--auth-session requires database access: %w", err)
		}
		repo := database.NewRepository(db)
		pid, _ := effectiveProjectUUID()
		rows, err := repo.GetAuthenticationHostnamesByHostname(ctx, pid, src.Hostname)
		if err != nil {
			return nil, fmt.Errorf("lookup auth sessions: %w", err)
		}
		found := false
		for _, row := range rows {
			if row.SessionName == replayAuthSession {
				for k, v := range row.Headers {
					overlay[k] = v
				}
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("auth session %q not found for hostname %s", replayAuthSession, src.Hostname)
		}
	}

	headers, err := parseReplayHeaderFlags()
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		overlay[k] = v
	}
	return overlay, nil
}

// parseReplayHeaderFlags parses the repeatable --header flags into an overlay
// map, erroring on the first malformed entry. Host-independent, so the bulk
// path parses it once and reuses it across records.
func parseReplayHeaderFlags() (map[string]string, error) {
	overlay := map[string]string{}
	for i, h := range replayHeaders {
		name, value, err := replay.ParseHeaderFlag(h)
		if err != nil {
			return nil, fmt.Errorf("--header[%d]: %w", i, err)
		}
		overlay[name] = value
	}
	return overlay, nil
}

func openReplayJar() (*jar.PersistentJar, int, error) {
	if replayNoCookies || replaySessionID == "" {
		return nil, 0, nil
	}
	path := jar.PathFor(replaySessionID)
	if path == "" {
		return nil, 0, fmt.Errorf("could not resolve jar path (set VIGOLIUM_HOME or HOME)")
	}
	return jar.Open(path)
}

func persistReplayResponse(ctx context.Context, src *replaySource, result *replay.Result) error {
	if src.RecordUUID == "" {
		return fmt.Errorf("--in-replace requires a stored record (got %s)", src.OriginLabel)
	}
	if result.Replay == nil || result.Replay.Error != "" {
		return fmt.Errorf("--in-replace skipped: replay had no usable response")
	}
	body := result.Replay.RawBody
	if body == nil {
		// Defensive: the engine populates RawBody on every successful
		// send. If we ever stop doing that, refuse rather than write
		// the clipped excerpt back as the canonical body.
		return fmt.Errorf("--in-replace skipped: engine did not return body bytes")
	}
	db, err := getDB()
	if err != nil {
		return err
	}
	repo := database.NewRepository(db)

	raw := rawReplayResponse(result.Replay)

	update := &database.RecordResponseUpdate{
		StatusCode:            result.Replay.Status,
		StatusPhrase:          http.StatusText(result.Replay.Status),
		ResponseHTTPVersion:   "HTTP/1.1",
		ResponseContentType:   result.Replay.Headers.Get("Content-Type"),
		ResponseContentLength: int64(result.Replay.ResponseLen),
		RawResponse:           raw,
		ResponseHash:          result.Replay.ContentHash,
		ResponseTimeMs:        result.Replay.ResponseTimeMs,
	}
	return repo.UpdateRecordResponse(ctx, src.RecordUUID, update)
}

func saveReplayResultToBurp(
	ctx context.Context,
	client *burpbridge.Client,
	src *replaySource,
	result *replay.Result,
) error {
	if client == nil {
		return fmt.Errorf("burp bridge client is not configured")
	}
	if result == nil || len(result.RawMutatedRequest) == 0 {
		return fmt.Errorf("replay did not return the complete sent request")
	}
	var rawResponse []byte
	if result.Replay != nil && result.Replay.Status > 0 && result.Replay.Error == "" {
		rawResponse = rawReplayResponse(result.Replay)
	}
	return client.AddToSiteMap(
		ctx,
		replaySourceURL(src),
		result.RawMutatedRequest,
		rawResponse,
		"vigolium-replay",
	)
}

// stageReplayToBurp pushes the just-sent request (and, where available, its
// response) into Burp's Repeater and/or Organizer for manual follow-up. The
// request was already issued (via Go or, under --send-via-burp, via Burp), so this
// only stages — it never re-sends.
func (rr *replayRun) stageReplayToBurp(ctx context.Context, src *replaySource, result *replay.Result) error {
	if rr.burpClient == nil {
		return fmt.Errorf("burp bridge client is not configured")
	}
	if result == nil || len(result.RawMutatedRequest) == 0 {
		return fmt.Errorf("replay did not return the complete sent request")
	}
	target := replaySourceURL(src)
	var rawResponse []byte
	if result.Replay != nil && result.Replay.Status > 0 && result.Replay.Error == "" {
		rawResponse = rawReplayResponse(result.Replay)
	}
	if rr.toRepeater {
		if _, err := rr.burpClient.SendToRepeater(ctx, target, "", result.RawMutatedRequest, burpbridge.RepeaterOptions{
			TabName: replayRepeaterTab,
		}); err != nil {
			return err
		}
	}
	if rr.toOrganizer {
		if _, err := rr.burpClient.SendToOrganizer(ctx, target, "", result.RawMutatedRequest, rawResponse, burpbridge.OrganizerOptions{
			Source:    "vigolium-replay",
			Notes:     replayNotes,
			Highlight: replayHighlight,
		}); err != nil {
			return err
		}
	}
	return nil
}

func replaySourceURL(src *replaySource) string {
	scheme := src.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := src.Hostname
	if src.Port > 0 {
		host = net.JoinHostPort(src.Hostname, strconv.Itoa(src.Port))
	}
	return (&url.URL{Scheme: scheme, Host: host}).String()
}

func rawReplayResponse(summary *replay.Summary) []byte {
	if summary == nil || summary.Status <= 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", summary.Status, http.StatusText(summary.Status))
	for k, values := range summary.Headers {
		for _, value := range values {
			fmt.Fprintf(&b, "%s: %s\r\n", k, value)
		}
	}
	b.WriteString("\r\n")
	return append([]byte(b.String()), summary.RawBody...)
}

// replayOutput is the JSON shape emitted to stdout / --output. It wraps
// the engine's Result with the source attribution and cookie-jar status
// the caller (often an agent) needs to chain calls.
type replayOutput struct {
	Source           string         `json:"source"`
	RecordUUID       string         `json:"record_uuid,omitempty"`
	FindingID        int64          `json:"finding_id,omitempty"`
	InputType        string         `json:"input_type,omitempty"`
	Target           string         `json:"target"`
	SessionID        string         `json:"session_id,omitempty"`
	CookiesPreloaded int            `json:"cookies_preloaded,omitempty"`
	JarPath          string         `json:"jar_path,omitempty"`
	Result           *replay.Result `json:"result"`
	SavedToBurp      bool           `json:"saved_to_burp,omitempty"`
	SentViaBurp      bool           `json:"sent_via_burp,omitempty"`
	StagedToRepeater bool           `json:"staged_to_repeater,omitempty"`
	SavedToOrganizer bool           `json:"saved_to_organizer,omitempty"`
	// Error is set (with Result nil) only in bulk mode when a single record
	// fails to replay, so one bad record doesn't abort the JSONL stream.
	Error string `json:"error,omitempty"`
}

func buildReplayOutput(src *replaySource, result *replay.Result, jarLoaded int, pj *jar.PersistentJar) *replayOutput {
	target := src.Hostname
	if src.Port > 0 {
		target = fmt.Sprintf("%s://%s:%d", src.Scheme, src.Hostname, src.Port)
	} else if src.Scheme != "" {
		target = fmt.Sprintf("%s://%s", src.Scheme, src.Hostname)
	}
	out := &replayOutput{
		Source:     src.OriginLabel,
		RecordUUID: src.RecordUUID,
		FindingID:  src.FindingID,
		InputType:  src.InputType,
		Target:     target,
		SessionID:  replaySessionID,
		Result:     result,
	}
	if pj != nil {
		out.JarPath = pj.Path()
		out.CookiesPreloaded = jarLoaded
	}
	return out
}

// openReplayOutputWriter returns the JSON sink for replay output: stdout, or
// --output if set. The returned close func is a no-op for stdout. Shared by the
// single-source (indented object) and bulk (JSONL stream) paths.
func openReplayOutputWriter() (io.Writer, func(), error) {
	if replayOutputPath == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(replayOutputPath)
	if err != nil {
		return nil, nil, fmt.Errorf("create --output %q: %w", replayOutputPath, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// emitReplayJSON pretty-prints the result. Agents that want compact
// JSON should pipe through `jq -c .`.
func emitReplayJSON(out *replayOutput) error {
	w, closeOut, err := openReplayOutputWriter()
	if err != nil {
		return err
	}
	defer closeOut()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func emitReplayPretty(out *replayOutput) error {
	fmt.Printf("%s %s\n", terminal.Cyan("→"), out.Source)
	fmt.Printf("  target: %s\n", out.Target)
	if out.SessionID != "" {
		fmt.Printf("  session: %s (preloaded %d cookies, jar: %s)\n",
			out.SessionID, out.CookiesPreloaded, out.JarPath)
	}
	if out.SentViaBurp {
		fmt.Printf("  sent via Burp's HTTP engine\n")
	}
	if out.SavedToBurp {
		fmt.Printf("  saved to Burp Target Site map\n")
	}
	if out.StagedToRepeater {
		fmt.Printf("  staged in Burp Repeater\n")
	}
	if out.SavedToOrganizer {
		fmt.Printf("  saved to Burp Organizer\n")
	}
	if out.Result == nil || out.Result.Replay == nil || out.Result.Baseline == nil {
		return fmt.Errorf("no result")
	}
	b, r, d := out.Result.Baseline, out.Result.Replay, out.Result.Diff
	tbl := terminal.NewTableWithMaxWidth(globalWidth, "", "BASELINE", "REPLAY")
	tbl.AddRow("Status",
		colorStatus(fmt.Sprintf("%d", b.Status), b.Status),
		colorStatus(fmt.Sprintf("%d", r.Status), r.Status))
	tbl.AddRow("Length",
		fmt.Sprintf("%d", b.ResponseLen),
		fmt.Sprintf("%d (Δ%+d)", r.ResponseLen, d.LengthDelta))
	tbl.AddRow("Hash", clicommon.Truncate(b.ContentHash, 16), clicommon.Truncate(r.ContentHash, 16))
	tbl.AddRow("Time (ms)",
		fmt.Sprintf("%d", b.ResponseTimeMs),
		fmt.Sprintf("%d", r.ResponseTimeMs))
	tbl.Print()
	if r.Error != "" {
		fmt.Printf("  %s replay error: %s\n", terminal.ErrorPrefix(), r.Error)
	}
	if d.Interpretation != "" {
		fmt.Printf("  %s %s\n", terminal.InfoSymbol(), d.Interpretation)
	}
	if len(d.ReflectsPayload) > 0 {
		fmt.Printf("  %s reflected payloads: %s\n", terminal.WarnPrefix(), strings.Join(d.ReflectsPayload, ", "))
	}
	if len(out.Result.Unmatched) > 0 {
		fmt.Printf("  %s unmatched insertion points: %s\n",
			terminal.WarnPrefix(), strings.Join(out.Result.Unmatched, ", "))
	}
	if out.Result.AdditionalGroups > 0 {
		fmt.Printf("  %s %d additional payload group(s) not sent — re-run to fire them\n",
			terminal.InfoSymbol(), out.Result.AdditionalGroups)
	}
	return nil
}
