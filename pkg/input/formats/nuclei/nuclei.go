package nuclei

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"go.uber.org/zap"
)

type NucleiOutput struct {
	URL     string `json:"url"`
	Request *struct {
		Raw string `json:"raw,omitempty"`
	} `json:"request"`
}

type NucleiFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new nuclei format parser
func New() *NucleiFormat {
	return &NucleiFormat{}
}

var _ formats.Format = &NucleiFormat{}

// Name returns the name of the format
func (j *NucleiFormat) Name() string {
	return "nuclei"
}

func (j *NucleiFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *NucleiFormat) Parse(input string, resultsCb formats.ParseReqRespCallback) error {
	file, err := j.openFile(input)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	dec := json.NewDecoder(file)

	for dec.More() {
		var outputResult NucleiOutput
		if err := dec.Decode(&outputResult); err != nil {
			// A decode error poisons json.Decoder: its read position does not
			// advance, so dec.More() stays true and Decode() returns the same error
			// on every iteration — a single malformed/truncated line would otherwise
			// spin this loop at 100% CPU forever. dec.More() already guards clean EOF,
			// so any error here is a real parse failure: stop parsing.
			zap.L().Warn("nuclei: stopping parse on malformed JSON", zap.Error(err))
			break
		}

		if outputResult.URL == "" {
			continue
		}

		var requestResponse *httpmsg.HttpRequestResponse
		var err error
		if outputResult.Request != nil && outputResult.Request.Raw != "" {
			requestResponse, err = httpmsg.ParseRawRequestWithURL(outputResult.Request.Raw, outputResult.URL)
		} else {
			requestResponse, err = httpmsg.GetRawRequestFromURL(outputResult.URL)
		}
		if err != nil {
			zap.L().Warn("nuclei: Could not parse raw request", zap.String("url", outputResult.URL), zap.Error(err))
			continue
		}

		// Honor the callback's cancellation signal, matching the other input formats.
		if !resultsCb(requestResponse) {
			return nil
		}
	}

	return nil
}

// Count returns the number of JSON objects in the file.
func (j *NucleiFormat) Count(input string) (int64, error) {
	file, err := j.openFile(input)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	var count int64
	dec := json.NewDecoder(file)
	for dec.More() {
		var obj json.RawMessage
		if err := dec.Decode(&obj); err != nil {
			// Same decoder-poison guard as Parse: stop on a malformed line rather
			// than spinning forever re-hitting the same error.
			break
		}
		count++
	}
	return count, nil
}

// openFile opens a file, handling .gz compression.
func (j *NucleiFormat) openFile(input string) (io.ReadCloser, error) {
	if strings.HasSuffix(input, ".gz") {
		gzFile, err := os.Open(input)
		if err != nil {
			return nil, errors.Wrap(err, "could not open gzipped file")
		}
		gzReader, err := gzip.NewReader(gzFile)
		if err != nil {
			_ = gzFile.Close()
			return nil, errors.Wrap(err, "could not create gzip reader")
		}
		return &gzipFileCloser{gzReader: gzReader, file: gzFile}, nil
	}
	return os.Open(input)
}

// gzipFileCloser wraps gzip.Reader and underlying file for proper cleanup.
type gzipFileCloser struct {
	gzReader *gzip.Reader
	file     *os.File
}

func (g *gzipFileCloser) Read(p []byte) (n int, err error) {
	return g.gzReader.Read(p)
}

func (g *gzipFileCloser) Close() error {
	_ = g.gzReader.Close()
	return g.file.Close()
}
