package wsdl

// Options contains options for parsing WSDL documents into SOAP requests.
type Options struct {
	// EndpointURL overrides the <soap:address location> declared in the WSDL.
	// Mirrors openapi.Options.BaseURL: when set, the scheme+host are taken from
	// this URL (so the in-scope target host is enforced) while the path declared
	// by the WSDL service address is preserved. When the WSDL has no service
	// address, EndpointURL is used verbatim. Empty means "use the WSDL's own
	// <soap:address> exactly".
	EndpointURL string

	// Headers are custom headers added to every generated SOAP request.
	Headers map[string]string

	// Variables maps XSD element/attribute local names to concrete values, used
	// in place of the synthesized placeholder when generating the sample body
	// (e.g. {"username": "admin"}). Analogous to openapi.Options.Variables.
	Variables map[string]string

	// SkipFormatValidation is accepted for parity with the generic
	// formats.InputFormatOptions; the WSDL generator is best-effort and never
	// hard-fails a single operation, so this is currently advisory.
	SkipFormatValidation bool
}
