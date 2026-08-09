package harvester

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// arquivoCDXURL is the Portuguese Web Archive's CDX endpoint. It speaks the
	// same wildcard dialect as the Wayback Machine, so the same `*.host/*` scope
	// works unchanged.
	arquivoCDXURL = "https://arquivo.pt/wayback/cdx"
	// arquivoMaxRows bounds one response. Unlike the Wayback and Common Crawl
	// endpoints, this one has no paging at all — `page` and `offset` are accepted
	// and ignored — so `limit` is the only thing standing between a large domain
	// and an unbounded response body.
	arquivoMaxRows = 5000
	arquivoTimeout = 60 * time.Second
)

// arquivoRecord is one NDJSON row of an Arquivo.pt CDX response.
type arquivoRecord struct {
	URL    string `json:"url"`
	MIME   string `json:"mime"`
	Status string `json:"status"`
}

// ArquivoSource collects URLs from the Portuguese Web Archive (arquivo.pt).
//
// It is a genuinely separate crawl rather than a mirror of the Internet Archive:
// its own crawlers, on their own schedule, with captures the Wayback Machine
// does not hold. That makes it additive for any target, and materially so for
// one with a European footprint.
type ArquivoSource struct {
	client  *http.Client
	baseURL string
}

// NewArquivoSource creates a new Arquivo.pt harvester source.
// proxyURL is optional; pass "" for no proxy.
func NewArquivoSource(proxyURL ...string) *ArquivoSource {
	var proxy string
	if len(proxyURL) > 0 {
		proxy = proxyURL[0]
	}
	return &ArquivoSource{
		client:  NewHTTPClient(arquivoTimeout, proxy),
		baseURL: arquivoCDXURL,
	}
}

func (s *ArquivoSource) Name() string   { return "arquivo" }
func (s *ArquivoSource) NeedsKey() bool { return false }

// Run fetches URLs for the domain from Arquivo.pt.
func (s *ArquivoSource) Run(ctx context.Context, domain string) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		if domain == "" {
			return
		}
		if err := s.stream(ctx, domain, results); err != nil {
			emit(ctx, results, Result{Source: s.Name(), Error: err})
		}
	}()

	return results
}

// stream queries the CDX index and emits every in-scope URL it reports.
func (s *ArquivoSource) stream(ctx context.Context, domain string, results chan<- Result) error {
	// The wildcards are written literally rather than escaped: the CDX API infers
	// its match type from them, so encoding either would turn "this domain and
	// everything under it" into a literal lookup that matches nothing. A domain
	// is a hostname, so it has nothing to escape.
	apiURL := fmt.Sprintf("%s?url=*.%s/*&output=json&fl=url,mime,status&limit=%d",
		s.baseURL, domain, arquivoMaxRows)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("arquivo.pt: unexpected status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var record arquivoRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if record.URL == "" {
			continue
		}
		// The archive answers a wildcard query with hosts that merely sort
		// nearby, so each row is re-checked on a label boundary rather than
		// trusted because the query asked for the right thing.
		if !minedURLInScope(record.URL, domain) {
			continue
		}

		emit(ctx, results, Result{Source: s.Name(), URL: record.URL})
	}
	return nil
}
