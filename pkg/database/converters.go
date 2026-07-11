package database

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/anomaly/htmlutils"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

const (
	// dnsPositiveTTL / dnsNegativeTTL bound how long a resolved / failed lookup is
	// trusted. A short negative TTL means a host that was briefly unreachable (or
	// resolved after the first miss) is retried soon, rather than being pinned to
	// "" for the process lifetime.
	dnsPositiveTTL = 10 * time.Minute
	dnsNegativeTTL = 30 * time.Second
	// dnsCacheMaxEntries bounds retained entries so a long-lived ingest server
	// scanning huge host sets can't grow the cache without limit.
	dnsCacheMaxEntries = 8192
)

// dnsEntry is a cached resolution with its expiry. A zero-value ip means the
// lookup failed (negative cache).
type dnsEntry struct {
	ip     string
	expiry time.Time
}

// dnsCache is a bounded, TTL'd hostname → resolution cache (LRU is internally
// synchronized, so no extra lock is needed).
var dnsCache = mustNewDNSCache()

func mustNewDNSCache() *lru.Cache[string, dnsEntry] {
	c, _ := lru.New[string, dnsEntry](dnsCacheMaxEntries)
	return c
}

// dnsInflight dedupes concurrent background resolves so each unresolved
// hostname spawns at most one in-flight lookup at a time.
var dnsInflight = struct {
	sync.Mutex
	m map[string]struct{}
}{m: make(map[string]struct{})}

// dnsResolveSem bounds how many background DNS lookups run concurrently, so a
// broad subdomain scan can't fan out into thousands of simultaneous resolvers.
var dnsResolveSem = make(chan struct{}, 16)

// resolveHostnameIP returns the cached IP for a hostname if known and fresh, and
// otherwise returns "" (or a stale value while refreshing) while scheduling the
// DNS lookup in the background.
//
// This deliberately does NOT block on net.LookupHost: it runs on the
// record-write/convert path (RecordWriter.Write -> FromHttpRequestResponse),
// where a dead or slow host would otherwise stall the writer for a full DNS
// timeout (~5s). IP is best-effort metadata, so the first record for a host may
// be persisted without it; once the background resolve completes, every later
// record for that host picks up the cached value. Literal IPs are still
// resolved synchronously (no DNS involved).
func resolveHostnameIP(hostname string) string {
	if e, ok := dnsCache.Get(hostname); ok {
		if time.Now().Before(e.expiry) {
			return e.ip // fresh hit (may be "" for a still-negative host)
		}
		// Expired: refresh off the write path, but serve the stale value meanwhile
		// so records aren't briefly stripped of a known IP on every TTL boundary.
		scheduleHostnameResolve(hostname)
		return e.ip
	}

	// If the hostname is already an IP address, cache and return it directly.
	if parsed := net.ParseIP(hostname); parsed != nil {
		dnsCache.Add(hostname, dnsEntry{ip: hostname, expiry: time.Now().Add(dnsPositiveTTL)})
		return hostname
	}

	// Not cached and needs a real DNS lookup: schedule it off the write path.
	scheduleHostnameResolve(hostname)
	return ""
}

// scheduleHostnameResolve kicks off a single background DNS resolve for hostname
// (deduped via dnsInflight, concurrency-bounded via dnsResolveSem) and caches
// the result with a TTL — a short negative TTL for failures so dead hosts are
// retried rather than pinned forever.
func scheduleHostnameResolve(hostname string) {
	dnsInflight.Lock()
	if _, busy := dnsInflight.m[hostname]; busy {
		dnsInflight.Unlock()
		return
	}
	dnsInflight.m[hostname] = struct{}{}
	dnsInflight.Unlock()

	go func() {
		dnsResolveSem <- struct{}{}
		addrs, err := net.LookupHost(hostname)
		<-dnsResolveSem

		resolved := ""
		if err == nil && len(addrs) > 0 {
			resolved = addrs[0]
		}
		ttl := dnsPositiveTTL
		if resolved == "" {
			ttl = dnsNegativeTTL
		}
		dnsCache.Add(hostname, dnsEntry{ip: resolved, expiry: time.Now().Add(ttl)})

		dnsInflight.Lock()
		delete(dnsInflight.m, hostname)
		dnsInflight.Unlock()
	}()
}

// FromHttpRequestResponse populates an HTTPRecord from httpmsg.HttpRequestResponse
func (r *HTTPRecord) FromHttpRequestResponse(ctx *httpmsg.HttpRequestResponse) error {
	if ctx == nil || ctx.Request() == nil {
		return fmt.Errorf("invalid HttpRequestResponse")
	}

	req := ctx.Request()
	u, err := ctx.URL()
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Generate UUID
	r.UUID = uuid.New().String()

	// Host info
	r.Scheme = u.Scheme
	r.Hostname = u.Hostname()
	port := 0
	if u.Port() != "" {
		_, _ = fmt.Sscanf(u.Port(), "%d", &port)
	} else if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	r.Port = port

	// Resolve hostname to IP (cached per hostname)
	if ip := resolveHostnameIP(r.Hostname); ip != "" {
		r.IP = ip
	}

	// Request fields
	r.Method = req.Method()
	r.Path = req.Path()
	r.HTTPVersion = "HTTP/1.1"
	r.URL = u.String()

	r.RequestContentType = req.Header("Content-Type")
	r.RequestContentLength = int64(len(req.Body()))

	// Request authorization (prefer Authorization header, fall back to Cookie)
	if auth := req.Header("Authorization"); auth != "" {
		r.RequestAuthorization = auth
	} else if cookie := req.Header("Cookie"); cookie != "" {
		r.RequestAuthorization = cookie
	}

	r.RawRequest = req.Raw()

	// Request hash
	hash := sha256.Sum256(r.RawRequest)
	r.RequestHash = hex.EncodeToString(hash[:])

	// Response (if available)
	if ctx.HasResponse() {
		resp := ctx.Response()
		r.HasResponse = true
		r.StatusCode = resp.StatusCode()
		r.ResponseHTTPVersion = extractResponseHTTPVersion(resp.Raw())

		r.ResponseContentType = resp.Header("Content-Type")
		r.ResponseContentLength = int64(len(resp.Body()))
		r.RawResponse = resp.Raw()

		respBody := resp.Body()
		if strings.Contains(strings.ToLower(r.ResponseContentType), "html") {
			r.ResponseTitle = extractHTMLTitle(respBody)
		}
		r.ResponseWords = countResponseWords(respBody, resp.Headers())

		respHash := sha256.Sum256(r.RawResponse)
		r.ResponseHash = hex.EncodeToString(respHash[:])

		// Reflected-URL-robust signature: strip the request path/URL the response
		// may echo back (e.g. an error page that mirrors the requested URI) and
		// collapse dynamic runs, so probes that differ only by the reflected target
		// dedup together instead of surviving as N near-identical records.
		r.ResponseNormHash = modkit.NormalizedBodyHash(string(respBody), r.Path, r.URL)

		r.ReceivedAt = time.Now()
	}

	// Parameters
	params, err := req.Parameters()
	if err == nil && len(params) > 0 {
		r.Parameters = make([]EmbeddedParam, 0, len(params))
		for _, p := range params {
			r.Parameters = append(r.Parameters, EmbeddedParam{
				Name:       p.Name(),
				Value:      p.Value(),
				Type:       ParameterTypeFromParamType(p.Type()),
				NameStart:  p.NameStart(),
				NameEnd:    p.NameEnd(),
				ValueStart: p.ValueStart(),
				ValueEnd:   p.ValueEnd(),
			})
		}
	}

	// Timestamps
	r.SentAt = time.Now()

	return nil
}

// FromResultEvent converts output.ResultEvent to Finding
func (f *Finding) FromResultEvent(event *output.ResultEvent) error {
	if event == nil {
		return fmt.Errorf("invalid ResultEvent")
	}

	f.ModuleID = event.ModuleID
	f.ModuleName = event.Info.Name
	f.Description = event.Info.Description
	f.Severity = event.Info.Severity.String()
	f.Confidence = event.Info.Confidence.String()
	f.Tags = event.Info.Tags

	f.URL = firstNonEmpty(event.URL, event.Matched)
	f.Hostname = resolveFindingHostname(event.Host, event.URL, event.Matched)

	if event.Matched != "" {
		f.MatchedAt = []string{event.Matched}
	}
	f.ExtractedResults = event.ExtractedResults

	f.Request = event.Request
	f.Response = event.Response
	// Static assets (JS/CSS/source maps) can be megabytes; on a finding we only
	// need the matched region in context. Store the response head (status line +
	// headers) verbatim plus a window of the body around the match. event.Response
	// is left untouched so the linked http_record still carries the full body for
	// display. Non-static responses are stored whole.
	if windowed, ok := windowStaticFindingResponse(f.URL, event.Response, event.ExtractedResults); ok {
		f.Response = windowed
	}
	// Cap evidence carried straight off the event (modules that collect many
	// request/response pairs themselves, e.g. OAST/timing collectors) to the same
	// ceiling the dedup merge paths enforce, so a single finding never persists an
	// unbounded payload.
	f.AdditionalEvidence = event.AdditionalEvidence
	if len(f.AdditionalEvidence) > maxAdditionalEvidence {
		f.AdditionalEvidence = f.AdditionalEvidence[:maxAdditionalEvidence]
	}
	f.ModuleType = event.ModuleType
	f.FindingSource = event.FindingSource
	f.RecordKind = string(event.EffectiveRecordKind())
	f.EvidenceGrade = string(event.EvidenceGrade)
	f.ModuleShort = event.ModuleShort

	// Classification: native modules already publish a CWE in the result event's
	// metadata map (Metadata["cwe"], e.g. "CWE-79"), but the finding's cwe_id
	// column — which exists and is rendered in reports — was never populated from
	// native results. Surface it so console/JSON/HTML/DB/API all carry it.
	f.CWEID = cweFromMetadata(event.Metadata)

	f.FindingHash = event.ID()
	f.FoundAt = time.Now()

	// Native scan results come from deterministic engines — they're trusted by
	// default and skip the triage queue. Caller may override (e.g. user import).
	f.Status = StatusTriaged

	return nil
}

// cweFromMetadata extracts a CWE identifier from a ResultEvent's metadata map.
// Native modules publish it as Metadata["cwe"], typically a single "CWE-nnn"
// string; a slice of strings/interfaces is joined. Returns "" when absent.
func cweFromMetadata(meta map[string]interface{}) string {
	if len(meta) == 0 {
		return ""
	}
	v, ok := meta["cwe"]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []string:
		return joinNonEmpty(t)
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return joinNonEmpty(parts)
	}
	return ""
}

// joinNonEmpty trims each element and joins the non-empty ones with ", ".
func joinNonEmpty(in []string) string {
	parts := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ", ")
}

// windowStaticFindingResponse returns a size-bounded copy of a finding's raw
// response when it belongs to a static asset (JS/CSS/source map/font/image/...),
// keeping the response head verbatim and windowing the body around the matched
// value (locators). It reports ok=false — leaving the caller's full response in
// place — for non-static content, an unparsable response head, an empty response,
// or a body small enough to store whole. Static-ness is decided by Content-Type,
// falling back to the URL's file extension so source maps served as
// application/json are still caught.
func windowStaticFindingResponse(findingURL, rawResponse string, locators []string) (string, bool) {
	opts := modkit.DefaultResponseWindowOpts()
	// Cheap pre-gate on the raw length: the body can't exceed the whole response,
	// so anything at or below the threshold is never windowed. This skips the
	// full-response copy and parse for the common small-response finding.
	if len(rawResponse) <= opts.FullThreshold {
		return "", false
	}

	resp := httpmsg.NewHttpResponse([]byte(rawResponse))
	head := resp.Head()
	if len(head) == 0 {
		return "", false // unparsable head — don't risk dropping it
	}
	body := resp.Body()
	if len(body) <= opts.FullThreshold {
		return "", false // body fits whole — keep the original, skip the rebuild
	}

	static := modkit.IsStaticAssetContentType(resp.Header("Content-Type"))
	if !static && findingURL != "" {
		if u, err := neturl.Parse(findingURL); err == nil {
			static = modkit.HasStaticAssetExtension(u.Path)
		}
	}
	if !static {
		return "", false
	}

	return string(head) + modkit.WindowBody(body, locators, 0, opts), true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// resolveFindingHostname picks the hostname for a finding, preferring the
// explicit Host field on the event, then parsing the URL or matched-at value.
func resolveFindingHostname(host, url, matched string) string {
	if host != "" {
		// event.Host is populated inconsistently by modules: some set the bare host
		// ("localhost"), others the authority with port ("localhost:3000"). The
		// findings table carries no port column, and the scan-completion summary +
		// hostname filters (CountFindingsBySeverity, GetFindingsByHostname) all match
		// the bare hostname stored on http_records. Normalize to the bare host so a
		// port-bearing event.Host doesn't get filtered out of those queries.
		return stripHostPort(host)
	}
	for _, candidate := range []string{url, matched} {
		if candidate == "" {
			continue
		}
		if parsed, err := neturl.Parse(candidate); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	return ""
}

// stripHostPort returns the bare host from an authority value, dropping any
// ":port" suffix. Handles IPv6 literals ("[::1]:3000" → "::1") and bare hosts
// (no port) unchanged. Parsing as "//host" lets net/url do the host[:port]
// (and bracketed-IPv6) splitting without us reimplementing it.
func stripHostPort(host string) string {
	if host == "" {
		return ""
	}
	if parsed, err := neturl.Parse("//" + host); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	// Fallback: parse failed (e.g. an unusual value) — keep the original so we
	// never lose the host entirely.
	return host
}

// extractResponseHTTPVersion extracts the HTTP version from the raw response status line.
// Falls back to "HTTP/1.1" if parsing fails or the version is missing/invalid
// (e.g. "HTTP/0.0", which Go's http.Response.Write produces for responses with
// unset ProtoMajor/ProtoMinor).
func extractResponseHTTPVersion(raw []byte) string {
	if len(raw) == 0 {
		return "HTTP/1.1"
	}
	// Find end of first line (status line)
	end := bytes.IndexByte(raw, '\n')
	if end < 0 {
		end = len(raw)
	}
	line := string(raw[:end])
	// Status line format: "HTTP/1.1 200 OK" — version is the first space-delimited token
	if idx := strings.IndexByte(line, ' '); idx > 0 {
		version := strings.TrimSpace(line[:idx])
		if isValidHTTPVersion(version) {
			return version
		}
	}
	return "HTTP/1.1"
}

// isValidHTTPVersion reports whether v looks like a real HTTP version token.
// Rejects empty/malformed values and "HTTP/0.x" (which standard library
// rendering emits for responses missing ProtoMajor/ProtoMinor).
func isValidHTTPVersion(v string) bool {
	if !strings.HasPrefix(v, "HTTP/") {
		return false
	}
	rest := v[len("HTTP/"):]
	if rest == "" {
		return false
	}
	// Major version is the leading digit(s). Require at least one non-zero digit.
	major := rest
	if dot := strings.IndexByte(rest, '.'); dot >= 0 {
		major = rest[:dot]
	}
	if major == "" {
		return false
	}
	for _, r := range major {
		if r < '0' || r > '9' {
			return false
		}
	}
	return strings.Trim(major, "0") != ""
}

// extractHTMLTitle parses the <title> element from an HTML body.
// Returns empty string on parse failure or missing title. Caps at 512 chars.
func extractHTMLTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	doc, err := htmlutils.FastParse(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	tags := htmlutils.GetElementsByTagName(doc, "title")
	if len(tags) == 0 {
		return ""
	}
	title := strings.TrimSpace(htmlutils.TextContent(tags[0]))
	if len(title) > 512 {
		title = title[:512]
	}
	return title
}

// countResponseWords counts whitespace-delimited words in the response body and headers.
// Uses byte-level scanning to avoid allocating a string copy or []string slice.
func countResponseWords(body []byte, headers []httpmsg.HttpHeader) int64 {
	count := int64(countWordsBytes(body))
	for _, h := range headers {
		count += int64(countWordsString(h.Name))
		count += int64(countWordsString(h.Value))
	}
	return count
}

// countWordsBytes counts whitespace-delimited words in a byte slice without allocations.
func countWordsBytes(b []byte) int {
	n := 0
	inWord := false
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}

// countWordsString counts whitespace-delimited words in a string without allocations.
func countWordsString(s string) int {
	n := 0
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			inWord = false
		} else if !inWord {
			inWord = true
			n++
		}
	}
	return n
}

// ParameterTypeFromParamType converts ParamType to database parameter type string
func ParameterTypeFromParamType(ptype httpmsg.ParamType) string {
	switch ptype {
	case httpmsg.ParamURL:
		return "url"
	case httpmsg.ParamBody, httpmsg.ParamBodyMultipart:
		return "body"
	case httpmsg.ParamJSON:
		return "json"
	case httpmsg.ParamXML, httpmsg.ParamXMLAttr:
		return "xml"
	case httpmsg.ParamCookie:
		return "cookie"
	case httpmsg.ParamPathFolder, httpmsg.ParamPathFilename:
		return "path"
	case httpmsg.ParamMultipartAttr:
		return "multipart"
	default:
		return "unknown"
	}
}
