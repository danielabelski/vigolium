package harvester

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

const (
	ccIndexURL     = "https://index.commoncrawl.org/collinfo.json"
	ccMaxYearsBack = 5
	// ccDataURL serves the WARC files the index points into. Every index row
	// carries the filename, byte offset and length of its record, so one ranged
	// request retrieves exactly one archived response — a few kilobytes, not the
	// multi-gigabyte file it lives in.
	ccDataURL = "https://data.commoncrawl.org/"
	// ccMineMaxRecords caps WARC records fetched per domain.
	ccMineMaxRecords = 20
)

type ccIndexEntry struct {
	ID     string `json:"id"`
	APIURL string `json:"cdx-api"`
}

// ccRecord is one NDJSON row of a Common Crawl CDX response.
type ccRecord struct {
	URL      string `json:"url"`
	MIME     string `json:"mime"`
	Status   string `json:"status"`
	Filename string `json:"filename"`
	Offset   string `json:"offset"`
	Length   string `json:"length"`
	Error    string `json:"error"`
}

// CommonCrawlSource collects URLs from the Common Crawl CDX index.
type CommonCrawlSource struct {
	client *http.Client
	// indexURL and dataURL are overridable so tests can stand in for the live
	// service; production callers take the defaults.
	indexURL string
	dataURL  string
}

// NewCommonCrawlSource creates a new Common Crawl harvester source.
// proxyURL is optional; pass "" for no proxy.
func NewCommonCrawlSource(proxyURL ...string) *CommonCrawlSource {
	var proxy string
	if len(proxyURL) > 0 {
		proxy = proxyURL[0]
	}
	return &CommonCrawlSource{
		client:   NewHTTPClient(60*time.Second, proxy),
		indexURL: ccIndexURL,
		dataURL:  ccDataURL,
	}
}

func (s *CommonCrawlSource) Name() string   { return "commoncrawl" }
func (s *CommonCrawlSource) NeedsKey() bool { return false }

// Run fetches URLs for the domain from Common Crawl indices.
func (s *CommonCrawlSource) Run(ctx context.Context, domain string) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		// Fetch index list
		indexes, err := s.fetchIndexes(ctx)
		if err != nil {
			results <- Result{Source: s.Name(), Error: fmt.Errorf("fetch indexes: %w", err)}
			return
		}

		// Select indices from last N years
		currentYear := time.Now().Year()
		years := make([]string, 0, ccMaxYearsBack)
		for i := range ccMaxYearsBack {
			years = append(years, strconv.Itoa(currentYear-i))
		}

		selectedAPIs := make(map[string]string)
		for _, year := range years {
			for _, idx := range indexes {
				if strings.Contains(idx.ID, year) {
					if _, exists := selectedAPIs[year]; !exists {
						selectedAPIs[year] = idx.APIURL
						break
					}
				}
			}
		}

		// Query each selected index
		var rows []cdxRow
		for _, apiURL := range selectedAPIs {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// The cap is on the accumulator, not on each collection: five
			// collections each filling their own budget would retain five times
			// what the selection actually reads.
			if len(rows) < mineMaxRows {
				rows = append(rows, s.queryIndex(ctx, apiURL, domain, results)...)
			} else {
				s.queryIndex(ctx, apiURL, domain, results)
			}
		}

		s.mineWARCs(ctx, domain, rows, results)
	}()

	return results
}

func (s *CommonCrawlSource) fetchIndexes(ctx context.Context) ([]ccIndexEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.indexURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var indexes []ccIndexEntry
	if err := json.NewDecoder(resp.Body).Decode(&indexes); err != nil {
		return nil, err
	}
	return indexes, nil
}

// queryIndex reads one collection, emitting every URL it reports and returning
// the rows so the WARC mining pass can locate the bodies worth reading.
//
// The response is NDJSON rather than plain text because the filename/offset/length
// triple is what makes mining possible, and those fields only exist in the JSON
// form.
func (s *CommonCrawlSource) queryIndex(ctx context.Context, apiURL, domain string, results chan<- Result) []cdxRow {
	searchURL := fmt.Sprintf("%s?url=*.%s&output=json&fl=url,mime,status,filename,offset,length", apiURL, domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		results <- Result{Source: s.Name(), Error: err}
		return nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		results <- Result{Source: s.Name(), Error: err}
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// A collection with nothing for the domain answers 404, which is an empty
	// result rather than a failure worth reporting.
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var rows []cdxRow

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return rows
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var record ccRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if record.Error != "" || record.URL == "" {
			continue
		}

		// Only mineable rows are retained — see the same filter in wayback.go.
		row := cdxRow{
			URL:      record.URL,
			MIME:     record.MIME,
			Status:   record.Status,
			Filename: record.Filename,
			Offset:   record.Offset,
			Length:   record.Length,
		}
		if mineWorthy(row) && len(rows) < mineMaxRows {
			rows = append(rows, row)
		}

		emit(ctx, results, Result{Source: s.Name(), URL: record.URL})
	}

	return rows
}

// mineWARCs reads a bounded selection of archived responses out of the WARC
// files and emits the URLs written inside them.
//
// Common Crawl's index is a list of pages it fetched; the pages themselves hold
// the links, forms and script-built endpoints that were never fetched and so
// never indexed. Retrieving one costs a single ranged request against a public
// bucket — no key, no crawl of the live site.
func (s *CommonCrawlSource) mineWARCs(ctx context.Context, domain string, rows []cdxRow, results chan<- Result) {
	e := emitter{ctx: ctx, ch: results, source: s.Name()}
	mineExtracted(domain, selectMineTargets(rows, ccMineMaxRecords), func(row cdxRow) []byte {
		return s.fetchWARCRecord(ctx, row)
	}, e)
}

// fetchWARCRecord retrieves and unwraps the archived response one index row
// points at.
func (s *CommonCrawlSource) fetchWARCRecord(ctx context.Context, row cdxRow) []byte {
	offset, err := strconv.ParseInt(row.Offset, 10, 64)
	if err != nil {
		return nil
	}
	length, err := strconv.ParseInt(row.Length, 10, 64)
	if err != nil || length <= 0 || length > mineMaxBodyBytes {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.dataURL+row.Filename, nil)
	if err != nil {
		return nil
	}
	// The record is one gzip member inside the WARC, so the range must cover it
	// exactly: a short read leaves a truncated stream that will not inflate.
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))

	resp, err := s.client.Do(req)
	if err != nil {
		zap.L().Debug("CommonCrawl: WARC fetch failed", zap.String("url", row.URL), zap.Error(err))
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// Anything but 206 means the range was ignored, and the body would then be
	// the whole multi-gigabyte file.
	if resp.StatusCode != http.StatusPartialContent {
		return nil
	}
	return warcResponseBody(readCappedBody(resp))
}

// warcResponseBody peels the two header blocks off a WARC response record: the
// WARC record headers, then the archived HTTP response's own headers. What
// remains is the body as the server sent it.
func warcResponseBody(record []byte) []byte {
	// Both separators appear in the wild — the spec says CRLF, but some writers
	// emit bare LF — and httpmsg's parser already handles either, plus the
	// end-of-buffer edge case.
	for range 2 {
		idx := httpmsg.FindHeaderBodySeparator(record, 0)
		if idx < 0 {
			return nil
		}
		record = record[idx:]
	}
	return record
}
