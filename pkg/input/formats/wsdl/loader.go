package wsdl

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const loadTimeout = 30 * time.Second

// LoadWSDL loads a WSDL document from a local file path or a URL. For a bare WCF
// `.svc` or ASMX `.asmx` URL (one with no query string), it appends the vendor
// query that returns the WSDL — `?singleWsdl` for WCF (which inlines every
// imported schema, sidestepping multi-file resolution) and `?WSDL` for ASMX — so
// callers can pass the live service URL directly.
func LoadWSDL(input string) ([]byte, error) {
	if isURL(input) {
		return loadFromURL(normalizeServiceURL(input))
	}
	return os.ReadFile(input)
}

func isURL(input string) bool {
	return strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
}

// normalizeServiceURL turns a bare .svc/.asmx endpoint URL into its WSDL URL. A
// URL that already carries a query (e.g. `?wsdl`, `?singleWsdl`) is left as-is.
func normalizeServiceURL(raw string) string {
	if strings.Contains(raw, "?") {
		return raw
	}
	lower := strings.ToLower(raw)
	switch {
	case strings.HasSuffix(lower, ".svc"):
		return raw + "?singleWsdl"
	case strings.HasSuffix(lower, ".asmx"):
		return raw + "?WSDL"
	}
	return raw
}

func loadFromURL(u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/wsdl+xml, text/xml, application/xml, */*")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch WSDL: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
