// Package wsdl parses WSDL 1.1 / SOAP service descriptions into concrete SOAP
// requests, so a `.wsdl` file or a live `.svc`/`.asmx` endpoint can be fed to
// the scanner the same way an OpenAPI/Swagger spec is. Each bound SOAP operation
// becomes one POST request carrying a synthesized SOAP envelope (SOAP 1.1 or
// 1.2, document/literal or rpc), whose XML body the active-module fleet can then
// fuzz via the existing XML insertion points.
//
// Scope: WSDL 1.1 with SOAP 1.1 and 1.2 bindings, document and rpc style. The
// XSD body generator is best-effort — deep/recursive schemas degrade to a finite
// skeleton and multi-file <import> is not resolved (fetch WCF `?singleWsdl`,
// which inlines schemas, for .svc). WSDL 2.0 is not supported.
package wsdl

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
)

// Format implements formats.Format for WSDL 1.1 / SOAP service descriptions.
type Format struct {
	formatOpts formats.InputFormatOptions
	wsdlOpts   Options
}

// New creates a new WSDL Format.
func New() *Format { return &Format{} }

// Name returns the canonical format name.
func (f *Format) Name() string { return "wsdl" }

// SetOptions sets the generic format options.
func (f *Format) SetOptions(options formats.InputFormatOptions) {
	f.formatOpts = options
}

// SetWSDLOptions sets WSDL-specific options (endpoint override, headers,
// per-field value overrides). Mirrors openapi.Format.SetOpenAPIOptions.
func (f *Format) SetWSDLOptions(opts Options) { f.wsdlOpts = opts }

// Parse loads a WSDL from a file or URL and calls callback for each generated
// SOAP request.
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	data, err := LoadWSDL(input)
	if err != nil {
		return fmt.Errorf("failed to load WSDL: %w", err)
	}

	opts := f.wsdlOpts
	opts.SkipFormatValidation = f.formatOpts.SkipFormatValidation

	return ParseData(data, opts, func(rr *httpmsg.HttpRequestResponse) bool {
		return callback(rr)
	})
}

// Count returns the number of bound SOAP operations (implements formats.Counter).
func (f *Format) Count(input string) (int64, error) {
	data, err := LoadWSDL(input)
	if err != nil {
		return 0, err
	}
	return CountOperations(data)
}
