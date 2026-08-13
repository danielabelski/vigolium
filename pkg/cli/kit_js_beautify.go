package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/harvester"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	kitBeautifyExtract bool
	kitBeautifyTimeout time.Duration
)

var kitJSBeautifyCmd = &cobra.Command{
	Use:   "js-beautify [file|url|-]",
	Short: "Unminify and unpack a JavaScript bundle into readable source",
	Long: `Unminify + unpack minified/bundled JavaScript into readable source using the
embedded jstangle tool (webcrack — unminify and bundle-unpack, no eval-based
deobfuscation). The argument is a local file, an http(s):// URL (fetched), or
'-'/no argument for stdin.

  vigolium kit js-beautify app.min.js                     # local file
  vigolium kit js-beautify https://acme.test/main.abc.js  # fetch + beautify
  cat bundle.js | vigolium kit js-beautify -              # stdin
  vigolium kit js-beautify -j --extract app.min.js        # + extracted endpoints

By default the beautified source is written to stdout. If the input is neither
minified nor bundled it is emitted unchanged (a note goes to stderr). --extract
also runs endpoint extraction and, with -j, includes discovered requests.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runKitJSBeautify,
}

func init() {
	f := kitJSBeautifyCmd.Flags()
	f.BoolVar(&kitBeautifyExtract, "extract", false, "Also extract endpoints/requests (a full analysis pass); included in -j output")
	f.DurationVar(&kitBeautifyTimeout, "timeout", 30*time.Second, "Timeout for fetching a URL argument")
	kitCmd.AddCommand(kitJSBeautifyCmd)
}

type kitBeautifyResult struct {
	Source      string                      `json:"source"`
	Changed     bool                        `json:"changed"`
	Format      string                      `json:"format,omitempty"`
	ModuleCount int                         `json:"module_count"`
	ModulePaths []string                    `json:"module_paths,omitempty"`
	BytesIn     int                         `json:"bytes_in"`
	BytesOut    int                         `json:"bytes_out"`
	Content     string                      `json:"content"`
	Endpoints   []jstangle.ExtractedRequest `json:"endpoints,omitempty"`
}

func runKitJSBeautify(cmd *cobra.Command, args []string) error {
	arg := "-"
	if len(args) == 1 {
		arg = args[0]
	}

	data, label, mediaType, err := kitResolveJSInput(arg)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("no input: %s is empty", label)
	}

	service, err := jstangle.DefaultService()
	if err != nil {
		return fmt.Errorf("jstangle unavailable (embedded binary missing or unsupported platform): %w", err)
	}

	opts := jstangle.ScanOptions{
		Profile:   jstangle.ProfileBeautify,
		SourceURL: label,
		Filename:  filepath.Base(label),
		MediaType: mediaType,
	}
	if kitBeautifyExtract {
		// Full pass: beautify AND endpoint extraction in one subprocess call.
		opts.Profile = jstangle.ProfileFull
		opts.Beautify = true
	}

	ctx := context.Background()
	res, scanErr := service.ScanWithOptions(ctx, data, opts)
	if scanErr != nil {
		if errors.Is(scanErr, jstangle.ErrUnsupportedProfile) {
			return fmt.Errorf("the embedded jstangle binary does not support the %q profile; update the binary", opts.Profile)
		}
		return fmt.Errorf("beautify failed: %w", scanErr)
	}

	result := kitBeautifyResult{Source: label, BytesIn: len(data), Content: string(data)}
	if res != nil && res.HasBeautified() {
		b := res.Beautified
		result.Changed = true
		result.Format = b.Format
		result.ModuleCount = b.ModuleCount
		result.ModulePaths = b.ModulePaths
		result.Content = b.Content
	}
	result.BytesOut = len(result.Content)
	if kitBeautifyExtract && res != nil {
		result.Endpoints = res.Requests
	}

	if globalJSON {
		return writeAgentJSON(result)
	}

	// Plain mode: the beautified (or unchanged) source is the payload on stdout;
	// status notes go to stderr so a pipe stays clean.
	if !result.Changed {
		fmt.Fprintf(os.Stderr, "%s %s is neither minified nor bundled — emitted unchanged\n",
			terminal.InfoSymbol(), label)
	} else {
		fmt.Fprintf(os.Stderr, "%s beautified %s (%s, %d module(s), %d → %d bytes)\n",
			terminal.InfoSymbol(), label, result.Format, result.ModuleCount, result.BytesIn, result.BytesOut)
	}
	fmt.Print(result.Content)
	if !strings.HasSuffix(result.Content, "\n") {
		fmt.Println()
	}
	if kitBeautifyExtract && len(result.Endpoints) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s %d endpoint(s) extracted (use -j to capture)\n",
			terminal.InfoSymbol(), len(result.Endpoints))
	}
	return nil
}

// kitResolveJSInput returns the bytes to beautify, a label (URL/path/"stdin"),
// and a media type. An http(s):// argument is fetched; everything else (stdin
// "-" or a file path) goes through the shared kitReadInput.
func kitResolveJSInput(arg string) (data []byte, label, mediaType string, err error) {
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		return kitFetchURL(arg)
	}
	b, label, err := kitReadInput(arg)
	return b, label, "application/javascript", err
}

// kitFetchURL GETs a URL through vigolium's proxy setting and returns the body.
func kitFetchURL(rawURL string) (data []byte, label, mediaType string, err error) {
	client := harvester.NewHTTPClient(kitBeautifyTimeout, globalProxy)
	req, rerr := http.NewRequest(http.MethodGet, rawURL, nil)
	if rerr != nil {
		return nil, rawURL, "", rerr
	}
	req.Header.Set("User-Agent", "vigolium-kit/js-beautify")
	resp, rerr := client.Do(req)
	if rerr != nil {
		return nil, rawURL, "", fmt.Errorf("fetching %s: %w", rawURL, rerr)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, rawURL, "", fmt.Errorf("fetching %s: HTTP %d", rawURL, resp.StatusCode)
	}
	body, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return nil, rawURL, "", fmt.Errorf("reading %s: %w", rawURL, rerr)
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/javascript"
	}
	return body, rawURL, ct, nil
}
