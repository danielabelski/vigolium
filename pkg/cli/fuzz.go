package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/burpbridge"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/fuzz"
	"github.com/vigolium/vigolium/pkg/replay"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	// Source.
	fuzzInput      string
	fuzzInputFile  string
	fuzzRecordUUID string
	fuzzTargetURL  string

	// Curl-style request builder (used with a positional URL).
	fuzzMethod  string
	fuzzHeaders []string
	fuzzData    string

	// Positions.
	fuzzSelector    string
	fuzzPoints      []string
	fuzzFuzzHeaders []string
	fuzzKeyword     string

	// Payloads.
	fuzzWordlists []string
	fuzzClasses   []string
	fuzzPayloads  []string

	// Matchers (keep) — long flags only; pflag shorthands are single-char.
	fuzzMC []string // status (accepts "all")
	fuzzMS []int
	fuzzMW []int
	fuzzML []int
	fuzzMR string
	fuzzMT int64

	// Exclude (drop).
	fuzzEC []int
	fuzzES []int
	fuzzEW []int
	fuzzEL []int
	fuzzER string
	fuzzET int64

	// Behaviour / output.
	fuzzNoCalibrate bool
	fuzzConcurrency int
	fuzzDelayMs     int
	fuzzTimeout     time.Duration
	fuzzNoRedirects bool
	fuzzOutputPath  string
	fuzzAllResults  bool
	fuzzPretty      bool
	fuzzFailOnMatch bool

	// Burp bridge.
	fuzzSendViaBurp        bool
	fuzzBurpBridgeURL      string
	fuzzHTTPMode           string
	fuzzSendTimeout        time.Duration
	fuzzMatchesToOrganizer bool
)

var fuzzCmd = &cobra.Command{
	Use:   "fuzz [url]",
	Short: "Inject payloads into a request and report per-payload response anomalies",
	Long: `Fuzz a single HTTP request: inject a payload set into chosen positions and stream
per-payload response signals (status, size, words, lines, time, reflection, baseline
delta) with match/exclude gating and auto-calibration against the target's
catch-all.

fuzz is a low-level PRIMITIVE, not a scanner. It sends exactly the payloads you give it
at exactly the positions you pick, and reports raw signals — it makes no vulnerability
decision and emits no findings. Bring your own intelligence (this is what a coding agent
drives): pick a position, pick a wordlist, read the anomalies. For opinionated,
confirmation-backed detection use the module scanner instead:
'vigolium scan-request -i req.txt -m xss,sqli -j'.

SOURCE (one of):
  vigolium fuzz https://acme.test/api?id=FUZZ         # positional URL (+ -X/-H/-d)
  vigolium fuzz -i req.txt                            # curl/raw HTTP/Burp/base64/URL/stdin
  vigolium fuzz -u <record-uuid>                      # a stored HTTP record as baseline
  cat req.txt | vigolium fuzz                         # piped request on stdin

POSITIONS (what to fuzz):
  a literal FUZZ marker anywhere (request line, path, header, body) wins if present;
  otherwise --fuzz method|path|params|param-name|headers|cookies|all (default: all
  discovered insertion points), or --point TYPE:name (e.g. URL_PARAM:id) / --header Name.

PAYLOADS (combine freely):
  --class <name,..>              built-in class: ` + strings.Join(fuzz.PayloadClasses(), ", ") + `
  -w/--wordlist <file|builtin>   builtins: ` + strings.Join(fuzz.BuiltinNames(), ", ") + `
  -p/--payload <literal>         inline payload (repeatable)

MATCHERS keep a response (OR; empty = keep all), EXCLUDES drop it (OR):
  --match-status-code 200,301  --match-size N  --match-words N  --match-lines N
  --match-regex <re>  --match-time <ms>   (and the --exclude-* equivalents to drop)
  --match-status-code all keeps every status. Auto-calibration (on by default) suppresses
  the target's wildcard/catch-all response; suppressed results carry "calibrated":true.

OUTPUT:
  default        JSONL (one object per send) to stdout — matched only unless --all-results
  -j/--json      stream JSONL to stderr, print ONE summary object to stdout (agent handle:
                 baseline, counts, ranked top anomalies, a ready follow-up query)
Honors HTTP_PROXY / HTTPS_PROXY for Burp inspection.

BURP ENGINE (needs --burp-bridge-url, the extension's loopback listener):
  --send-via-burp         send every payload through Burp's own HTTP stack so exact bytes
                          hit the wire — the way to fuzz malformed/smuggling requests
                          (pair with --http-mode http1 so 'auto' doesn't reframe them)
  --matches-to-organizer  hand each matched request to Burp's Organizer (Burp re-issues it)
                          for manual triage
Neither changes the default send path — without them fuzz sends via Go's client as before.

fuzz reports raw signals, not verdicts — for confirmation-backed detection of known
classes use 'vigolium scan-request -m xss,sqli -j' instead.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runFuzz,
}

func init() {
	rootCmd.AddCommand(fuzzCmd)
	f := fuzzCmd.Flags()

	// Source.
	f.StringVarP(&fuzzInput, "input", "i", "", "Raw input: curl, raw HTTP, Burp XML, base64, URL, or '-' for stdin")
	f.StringVar(&fuzzInputFile, "input-file", "", "Read --input value from a file")
	f.StringVarP(&fuzzRecordUUID, "record-uuid", "u", "", "Use a stored HTTP record (by UUID) as the request to fuzz")
	f.StringVarP(&fuzzTargetURL, "target", "t", "", "Override scheme/host/port the request is sent to (e.g. https://staging.acme.test)")

	// Curl-style builder.
	f.StringVarP(&fuzzMethod, "request", "X", "GET", "HTTP method when building from a positional URL")
	f.StringArrayVarP(&fuzzHeaders, "header", "H", nil, "Request header 'Name: value' when building from a positional URL (repeatable)")
	f.StringVarP(&fuzzData, "data", "d", "", "Request body when building from a positional URL")

	// Positions.
	f.StringVar(&fuzzSelector, "fuzz", "", "What to fuzz: method|path|params|param-name|headers|cookies|all (default: all insertion points)")
	f.StringArrayVar(&fuzzPoints, "point", nil, "Explicit insertion point 'TYPE:name' e.g. URL_PARAM:id (repeatable)")
	f.StringArrayVar(&fuzzFuzzHeaders, "fuzz-header", nil, "Fuzz a specific header by name (repeatable)")
	f.StringVar(&fuzzKeyword, "keyword", fuzz.DefaultKeyword, "Marker keyword replaced by each payload when present in the request")

	// Payloads.
	f.StringSliceVar(&fuzzClasses, "class", nil, "Built-in payload class to inject: "+strings.Join(fuzz.PayloadClasses(), ",")+" (comma-list)")
	f.StringArrayVarP(&fuzzWordlists, "wordlist", "w", nil, "Payload wordlist: a builtin name or file path (repeatable)")
	f.StringArrayVarP(&fuzzPayloads, "payload", "p", nil, "Inline payload literal (repeatable)")

	// Matchers.
	f.StringSliceVar(&fuzzMC, "match-status-code", nil, "Match status codes (comma-list, or 'all')")
	f.IntSliceVar(&fuzzMS, "match-size", nil, "Match response sizes (bytes)")
	f.IntSliceVar(&fuzzMW, "match-words", nil, "Match response word counts")
	f.IntSliceVar(&fuzzML, "match-lines", nil, "Match response line counts")
	f.StringVar(&fuzzMR, "match-regex", "", "Match response body against this regex")
	f.Int64Var(&fuzzMT, "match-time", 0, "Match responses taking at least this many ms")

	// Exclude (drop) — the inverse of the matchers above.
	f.IntSliceVar(&fuzzEC, "exclude-status-code", nil, "Exclude these status codes")
	f.IntSliceVar(&fuzzES, "exclude-size", nil, "Exclude these response sizes (bytes)")
	f.IntSliceVar(&fuzzEW, "exclude-words", nil, "Exclude these response word counts")
	f.IntSliceVar(&fuzzEL, "exclude-lines", nil, "Exclude these response line counts")
	f.StringVar(&fuzzER, "exclude-regex", "", "Exclude responses whose body matches this regex")
	f.Int64Var(&fuzzET, "exclude-time", 0, "Exclude responses taking at least this many ms")

	// Behaviour / output.
	f.BoolVar(&fuzzNoCalibrate, "no-calibrate", false, "Disable auto-calibration of the target's catch-all response")
	f.IntVarP(&fuzzConcurrency, "concurrency", "c", 10, "Concurrent requests")
	f.IntVar(&fuzzDelayMs, "delay", 0, "Delay in ms before each request (per worker)")
	f.DurationVar(&fuzzTimeout, "timeout", replay.DefaultTimeout, "Per-request timeout (e.g. 30s)")
	f.BoolVar(&fuzzNoRedirects, "no-redirects", false, "Don't follow 30x redirects")
	f.StringVarP(&fuzzOutputPath, "output", "o", "", "Write JSONL results to this file (default: stdout)")
	f.BoolVar(&fuzzAllResults, "all-results", false, "Emit every result, not just matched ones")
	f.BoolVar(&fuzzPretty, "pretty", false, "Human-readable table instead of JSONL")
	f.BoolVar(&fuzzFailOnMatch, "fail-on-match", false, "Exit non-zero (3) if any result matches (for agent/CI gating)")

	// Burp bridge — route each payload through Burp's engine (exact bytes) and,
	// optionally, hand matched anomalies to Burp's Organizer for triage.
	f.BoolVar(&fuzzSendViaBurp, "send-via-burp", false,
		"Send each payload through Burp's own HTTP stack (exact bytes — malformed/smuggling preserved) instead of Go's client; requires --burp-bridge-url")
	f.StringVarP(&fuzzBurpBridgeURL, "burp-bridge-url", "B", burpbridge.URLFromEnvironment(),
		"Loopback Burp bridge URL used by --send-via-burp / --matches-to-organizer")
	f.StringVar(&fuzzHTTPMode, "http-mode", "",
		"With --send-via-burp: wire protocol — auto|http1|http2|http2_ignore_alpn (default auto; use http1 for request smuggling/desync)")
	f.DurationVar(&fuzzSendTimeout, "send-timeout", 0,
		"With --send-via-burp: per-request response timeout (<=2m; default uses the bridge's 30s)")
	f.BoolVar(&fuzzMatchesToOrganizer, "matches-to-organizer", false,
		"Push each matched result's request to Burp's Organizer (Burp re-issues it) for manual triage; requires --burp-bridge-url")
}

// fuzzOrganizerCap bounds how many matched requests are pushed to Burp's
// Organizer, so a wide-open match set can't flood Burp with tabs/items.
const fuzzOrganizerCap = 200

func runFuzz(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	ctx := cmd.Context()

	src, err := resolveFuzzSource(ctx, args)
	if err != nil {
		return err
	}
	if fuzzTargetURL != "" {
		if err := applyTargetOverride(src, fuzzTargetURL); err != nil {
			return err
		}
	}
	// A line-trimming stdin reader can strip the request's header terminator;
	// repair it so insertion-point analysis and the send path both parse.
	src.BaselineRequest = fuzz.NormalizeRawRequest(src.BaselineRequest)

	bridge, err := setupFuzzBurpBridge(ctx, src)
	if err != nil {
		return err
	}

	positions, err := fuzz.ResolvePositions(src.BaselineRequest, fuzz.Selectors{
		Mode:        fuzzSelector,
		NamedPoints: fuzzPoints,
		HeaderNames: fuzzFuzzHeaders,
		Keyword:     fuzzKeyword,
	})
	if err != nil {
		return err
	}

	payloads, err := fuzz.LoadPayloads(fuzzWordlists, fuzzClasses, fuzzPayloads)
	if err != nil {
		return err
	}

	matchers, err := buildMatchers()
	if err != nil {
		return err
	}
	filters, err := buildFilters()
	if err != nil {
		return err
	}

	// Result-stream sink. Under -j, stdout is reserved for the single summary
	// object, so per-payload JSONL streams to stderr (the agent can still tail
	// it); an explicit -o file always wins.
	out := os.Stdout
	switch {
	case fuzzOutputPath != "":
		f, err := os.Create(fuzzOutputPath)
		if err != nil {
			return fmt.Errorf("create --output %q: %w", fuzzOutputPath, err)
		}
		defer func() { _ = f.Close() }()
		out = f
	case globalJSON:
		out = os.Stderr
	}
	enc := json.NewEncoder(out)

	fmt.Fprintf(os.Stderr, "%s fuzzing %s://%s (%d positions × %d payloads = %d sends)\n",
		terminal.InfoSymbol(), src.Scheme, src.Hostname, len(positions), len(payloads), len(positions)*len(payloads))

	// OnResult is called serially by the engine, so no extra locking is needed
	// to accumulate the ranked top anomalies for the -j summary.
	var topResults []fuzz.Result
	job := fuzz.Job{
		Raw:           src.BaselineRequest,
		Scheme:        src.Scheme,
		Hostname:      src.Hostname,
		Port:          src.Port,
		Positions:     positions,
		Payloads:      payloads,
		Matchers:      matchers,
		Filters:       filters,
		AutoCalibrate: !fuzzNoCalibrate,
		Client:        replay.NewDefaultClient(nil, fuzzTimeout),
		NoRedirects:   fuzzNoRedirects,
		Concurrency:   fuzzConcurrency,
		DelayMs:       fuzzDelayMs,
		OnResult: func(r fuzz.Result) {
			if fuzzAllResults || r.Matched {
				if fuzzPretty {
					_, _ = fmt.Fprintln(out, prettyResult(r))
				} else {
					_ = enc.Encode(r)
				}
			}
			if globalJSON && r.Matched && len(topResults) < fuzzTopResultsCollect {
				topResults = append(topResults, r)
			}
		},
	}
	// --send-via-burp: every send goes through Burp's engine byte-for-byte.
	if bridge != nil && bridge.sendViaBurp {
		job.Sender = burpbridge.BridgeSender(bridge.client, src.Scheme, src.Hostname, src.Port, bridge.sendOpts, fuzzExcerptCap())
	}
	// --matches-to-organizer: collect matched requests (cheap, on the engine's
	// serialized path) so they can be handed to Burp's Organizer after the run
	// without blocking sends.
	var organizerMatches []fuzzOrganizerMatch
	var organizerOverflow int
	if bridge != nil && bridge.toOrganizer {
		job.OnMatch = func(r fuzz.Result, rawRequest []byte) {
			if len(organizerMatches) >= fuzzOrganizerCap {
				organizerOverflow++
				return
			}
			organizerMatches = append(organizerMatches, fuzzOrganizerMatch{
				rawRequest: append([]byte(nil), rawRequest...),
				notes:      fmt.Sprintf("fuzz %s:%s=%s", r.PositionType, r.Position, r.Payload),
				highlight:  fuzzMatchHighlight(r),
			})
		}
	}

	report, runErr := fuzz.Run(ctx, job)
	if report != nil {
		fmt.Fprintf(os.Stderr, "%s baseline: status=%d len=%d | sent=%d matched=%d calibrated=%d errors=%d\n",
			terminal.InfoSymbol(), report.Baseline.Status, report.Baseline.Length,
			report.Sent, report.Matched, report.Calibrated, report.Errors)
	}
	if runErr != nil {
		return runErr
	}

	organizerPushed := 0
	if bridge != nil && bridge.toOrganizer {
		organizerPushed = pushFuzzMatchesToOrganizer(ctx, bridge, src, organizerMatches, organizerOverflow)
	}

	if globalJSON && report != nil {
		if err := emitFuzzJSONSummary(src, args, len(positions), len(payloads), report, topResults, bridge != nil && bridge.sendViaBurp, organizerPushed); err != nil {
			return err
		}
	}
	if fuzzFailOnMatch && report != nil && report.Matched > 0 {
		os.Exit(3)
	}
	return nil
}

// fuzzBurpBridge holds the resolved bridge client and send settings for a fuzz
// run; nil when no Burp flag was set.
type fuzzBurpBridge struct {
	client      *burpbridge.Client
	sendViaBurp bool
	toOrganizer bool
	sendOpts    burpbridge.SendOptions
}

// fuzzOrganizerMatch is one matched request queued for Burp's Organizer.
type fuzzOrganizerMatch struct {
	rawRequest []byte
	notes      string
	highlight  string
}

// setupFuzzBurpBridge validates the bridge flags and preflights the listener so
// an unavailable bridge fails clearly up front. Returns nil (no error) when no
// Burp flag is set — the default send path is untouched.
func setupFuzzBurpBridge(ctx context.Context, _ *replaySource) (*fuzzBurpBridge, error) {
	if !fuzzSendViaBurp && !fuzzMatchesToOrganizer {
		if fuzzHTTPMode != "" {
			fmt.Fprintf(os.Stderr, "%s --http-mode only applies with --send-via-burp; ignoring\n", terminal.WarningSymbol())
		}
		return nil, nil
	}
	if strings.TrimSpace(fuzzBurpBridgeURL) == "" {
		return nil, fmt.Errorf("--send-via-burp/--matches-to-organizer require --burp-bridge-url")
	}
	httpMode, err := burpbridge.ParseHTTPMode(fuzzHTTPMode)
	if err != nil {
		return nil, fmt.Errorf("--http-mode: %w", err)
	}
	if fuzzHTTPMode != "" && !fuzzSendViaBurp {
		fmt.Fprintf(os.Stderr, "%s --http-mode only applies with --send-via-burp; ignoring\n", terminal.WarningSymbol())
	}
	validated, err := burpbridge.ValidateURL(fuzzBurpBridgeURL)
	if err != nil {
		return nil, fmt.Errorf("--burp-bridge-url: %w", err)
	}
	client, err := burpbridge.New(validated)
	if err != nil {
		return nil, err
	}
	info, err := client.Health(ctx)
	if err != nil {
		return nil, fmt.Errorf("burp bridge unavailable: %w", err)
	}
	if info.InScopeOnly {
		fmt.Fprintf(os.Stderr, "%s Burp bridge is in-scope-only; out-of-scope targets will be refused (403)\n", terminal.WarningSymbol())
	}
	return &fuzzBurpBridge{
		client:      client,
		sendViaBurp: fuzzSendViaBurp,
		toOrganizer: fuzzMatchesToOrganizer,
		sendOpts:    burpbridge.SendOptions{Mode: httpMode, Timeout: fuzzSendTimeout},
	}, nil
}

// pushFuzzMatchesToOrganizer hands each collected match to Burp's Organizer,
// letting Burp re-issue the request (send:true) so the stored item carries a
// live response for manual triage. Runs after the fuzz loop so it never slows
// sending; per-item failures are counted, not fatal.
func pushFuzzMatchesToOrganizer(ctx context.Context, bridge *fuzzBurpBridge, src *replaySource, matches []fuzzOrganizerMatch, overflow int) int {
	if len(matches) == 0 {
		return 0
	}
	target := replaySourceURL(src)
	pushed, failed := 0, 0
	for _, m := range matches {
		_, err := bridge.client.SendToOrganizer(ctx, target, "", m.rawRequest, nil, burpbridge.OrganizerOptions{
			Source:    "vigolium-fuzz",
			Notes:     m.notes,
			Highlight: m.highlight,
			Send:      true,
			Mode:      bridge.sendOpts.Mode,
			Timeout:   bridge.sendOpts.Timeout,
		})
		if err != nil {
			failed++
			continue
		}
		pushed++
	}
	fmt.Fprintf(os.Stderr, "%s pushed %d matched request(s) to Burp Organizer", terminal.InfoSymbol(), pushed)
	if failed > 0 {
		fmt.Fprintf(os.Stderr, " (%d failed)", failed)
	}
	if overflow > 0 {
		fmt.Fprintf(os.Stderr, "; %d more matched but the %d-item cap was hit", overflow, fuzzOrganizerCap)
	}
	fmt.Fprintln(os.Stderr)
	return pushed
}

// fuzzMatchHighlight picks a Burp Organizer highlight colour by anomaly type so
// a batch is visually triageable: status change (red), reflection (orange), else
// yellow.
func fuzzMatchHighlight(r fuzz.Result) string {
	switch {
	case r.StatusChanged:
		return "red"
	case r.Reflected:
		return "orange"
	default:
		return "yellow"
	}
}

// fuzzExcerptCap returns the excerpt clip size used for the run (mirrors the
// engine default) so the Burp sender's Summary excerpt matches the native path.
func fuzzExcerptCap() int {
	return replay.DefaultExcerptCap
}

// resolveFuzzSource picks the request to fuzz from a positional URL, -i/--input,
// -u/--record-uuid, or piped stdin — reusing replay's source resolvers.
func resolveFuzzSource(ctx context.Context, args []string) (*replaySource, error) {
	set := 0
	if len(args) == 1 {
		set++
	}
	if fuzzInput != "" || fuzzInputFile != "" {
		set++
	}
	if fuzzRecordUUID != "" {
		set++
	}
	if set > 1 {
		return nil, fmt.Errorf("choose one source: a positional URL, --input/--input-file, or --record-uuid")
	}

	var repo *database.Repository
	if db, dbErr := openReadDB(globDBSkipSet{}); dbErr == nil {
		repo = database.NewRepository(db)
	}

	switch {
	case len(args) == 1:
		rr, err := buildRequestFromFlags(args[0], fuzzMethod, fuzzData, fuzzHeaders)
		if err != nil {
			return nil, err
		}
		u, err := rr.URL()
		if err != nil || u == nil || u.URL == nil {
			return nil, fmt.Errorf("could not derive URL from %q", args[0])
		}
		return &replaySource{
			BaselineRequest: rr.Request().Raw(),
			Scheme:          u.Scheme,
			Hostname:        u.Hostname(),
			Port:            portFromURL(u.URL),
		}, nil

	case fuzzInput != "" || fuzzInputFile != "":
		return sourceFromInput(ctx, repo, fuzzInput, fuzzInputFile)

	case fuzzRecordUUID != "":
		if repo == nil {
			return nil, fmt.Errorf("--record-uuid requires database access")
		}
		return sourceFromRecord(ctx, repo, fuzzRecordUUID)

	default:
		if data, ok := readStdinIfPiped(); ok {
			return sourceFromInputString(ctx, repo, data, "")
		}
		return nil, fmt.Errorf("no source: pass a URL, --input, --record-uuid, or pipe a request on stdin")
	}
}

func buildMatchers() (fuzz.Matchers, error) {
	m := fuzz.Matchers{Sizes: fuzzMS, Words: fuzzMW, Lines: fuzzML, TimeMs: fuzzMT}
	for _, s := range fuzzMC {
		if strings.EqualFold(s, "all") {
			m.AllStatus = true
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return m, fmt.Errorf("bad --match-status-code value %q: want an int or 'all'", s)
		}
		m.Status = append(m.Status, n)
	}
	if fuzzMR != "" {
		re, err := regexp.Compile(fuzzMR)
		if err != nil {
			return m, fmt.Errorf("bad --match-regex: %w", err)
		}
		m.Regex = re
	}
	return m, nil
}

func buildFilters() (fuzz.Filters, error) {
	f := fuzz.Filters{Status: fuzzEC, Sizes: fuzzES, Words: fuzzEW, Lines: fuzzEL, TimeMs: fuzzET}
	if fuzzER != "" {
		re, err := regexp.Compile(fuzzER)
		if err != nil {
			return f, fmt.Errorf("bad --exclude-regex: %w", err)
		}
		f.Regex = re
	}
	return f, nil
}

const (
	// fuzzTopResultsCollect caps how many matched results are held in memory to
	// rank for the -j summary; fuzzTopResultsEmit caps how many are printed.
	fuzzTopResultsCollect = 500
	fuzzTopResultsEmit    = 20
)

// fuzzJSONSummary is the single object printed to stdout under -j: a compact,
// agent-friendly handle on the run (baseline, counts, ranked anomalies, and a
// ready confirmation command) so an agent needn't parse the JSONL stream.
type fuzzJSONSummary struct {
	Target          string        `json:"target"`
	Positions       int           `json:"positions"`
	Payloads        int           `json:"payloads"`
	Sent            int           `json:"sent"`
	Matched         int           `json:"matched"`
	Calibrated      int           `json:"calibrated"`
	Errors          int           `json:"errors"`
	Baseline        fuzz.Baseline `json:"baseline"`
	TopResults      []fuzz.Result `json:"top_results"`
	Query           string        `json:"query,omitempty"`
	SentViaBurp     bool          `json:"sent_via_burp,omitempty"`
	OrganizerPushed int           `json:"organizer_pushed,omitempty"`
}

func emitFuzzJSONSummary(src *replaySource, args []string, positions, payloadCount int, report *fuzz.Report, top []fuzz.Result, sentViaBurp bool, organizerPushed int) error {
	sort.SliceStable(top, func(i, j int) bool { return fuzzResultRank(top[i]) > fuzzResultRank(top[j]) })
	if len(top) > fuzzTopResultsEmit {
		top = top[:fuzzTopResultsEmit]
	}
	return writeAgentJSON(fuzzJSONSummary{
		Target:          fmt.Sprintf("%s://%s", src.Scheme, src.Hostname),
		Positions:       positions,
		Payloads:        payloadCount,
		Sent:            report.Sent,
		Matched:         report.Matched,
		Calibrated:      report.Calibrated,
		Errors:          report.Errors,
		Baseline:        report.Baseline,
		TopResults:      top,
		Query:           fuzzFollowUpQuery(args, report.Matched),
		SentViaBurp:     sentViaBurp,
		OrganizerPushed: organizerPushed,
	})
}

// fuzzResultRank scores a matched result so the most investigation-worthy
// anomalies sort first: a changed status, then reflection, then the magnitude
// of the size delta, then response time.
func fuzzResultRank(r fuzz.Result) int {
	score := 0
	if r.StatusChanged {
		score += 1_000_000
	}
	if r.Reflected {
		score += 500_000
	}
	delta := r.LengthDelta
	if delta < 0 {
		delta = -delta
	}
	score += delta
	score += int(r.TimeMs)
	return score
}

// fuzzFollowUpQuery returns a copy-pasteable command to confirm anomalies with
// the hardened module scanner, seeded from the same source the user supplied.
// Empty when nothing matched or the source can't be re-expressed as a flag.
func fuzzFollowUpQuery(args []string, matched int) string {
	if matched == 0 {
		return ""
	}
	var srcArg string
	switch {
	case len(args) == 1:
		srcArg = "-i '" + args[0] + "'"
	case fuzzInputFile != "":
		srcArg = "-i " + fuzzInputFile
	case fuzzInput != "" && fuzzInput != "-":
		srcArg = "-i '" + fuzzInput + "'"
	default:
		return ""
	}
	return "vigolium scan-request " + srcArg + " -m " + fuzzConfirmModules() + " -j   # confirm anomalies with hardened modules"
}

// fuzzConfirmModules maps the payload classes used into module-selection terms
// for the confirmation follow-up, defaulting to a broad injection set.
func fuzzConfirmModules() string {
	if len(fuzzClasses) > 0 {
		return strings.Join(fuzzClasses, ",")
	}
	return "xss,sqli,lfi,ssrf,cmdi"
}

func prettyResult(r fuzz.Result) string {
	flags := ""
	if r.Reflected {
		flags += " reflected"
	}
	if r.StatusChanged {
		flags += " status-changed"
	}
	if r.Error != "" {
		return fmt.Sprintf("  %-24s %-40q ERROR %s", r.PositionType+":"+r.Position, r.Payload, r.Error)
	}
	return fmt.Sprintf("  %-24s %-40q status=%-3d len=%-7d words=%-5d lines=%-4d %dms%s",
		r.PositionType+":"+r.Position, r.Payload, r.Status, r.Length, r.Words, r.Lines, r.TimeMs, flags)
}
