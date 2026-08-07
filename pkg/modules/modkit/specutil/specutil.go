package specutil

import (
	"bytes"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/formats/postman"
	"github.com/vigolium/vigolium/pkg/input/formats/wsdl"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

const (
	// MinSpecBodySize is the minimum body size to consider for spec detection.
	MinSpecBodySize = 50
	// MaxSpecBodySize is the maximum body size to consider for spec detection (10 MB).
	MaxSpecBodySize = 10 * 1024 * 1024
)

// SpecType represents the type of API specification.
type SpecType int

const (
	Unknown SpecType = iota
	OpenAPI
	Postman
	WSDL
)

// Label returns a human-readable name for the spec type, used in the "discovered
// a spec" progress notices so a WSDL isn't announced as an OpenAPI spec.
func (t SpecType) Label() string {
	switch t {
	case OpenAPI:
		return "OpenAPI/Swagger spec"
	case Postman:
		return "Postman collection"
	case WSDL:
		return "WSDL/SOAP service"
	default:
		return "API spec"
	}
}

// DetectSpecType determines whether data is an OpenAPI/Swagger, Postman, or
// WSDL/SOAP service description. WSDL is checked first: it is XML, disjoint from
// the JSON/YAML specs, and its marker gate is strict (definitions + WSDL + SOAP
// namespaces), so it cannot be confused with the others.
func DetectSpecType(data []byte) SpecType {
	if wsdl.IsWSDL(data) {
		return WSDL
	}
	if openapi.IsOpenAPISpec(data) {
		return OpenAPI
	}
	// Postman markers: "_postman_id" or schema.getpostman.com
	if bytes.Contains(data, []byte(`"_postman_id"`)) ||
		bytes.Contains(data, []byte(`schema.getpostman.com`)) {
		return Postman
	}
	return Unknown
}

// ParseSpec parses a spec of the given type and returns all extracted endpoints.
// If specType is Unknown, it auto-detects. Each endpoint is optionally stamped with the given service.
func ParseSpec(data []byte, baseURL string, service *httpmsg.Service) ([]*httpmsg.HttpRequestResponse, error) {
	return ParseSpecTyped(DetectSpecType(data), data, baseURL, service)
}

// ParseSpecTyped parses a spec of a known type, skipping detection.
func ParseSpecTyped(specType SpecType, data []byte, baseURL string, service *httpmsg.Service) ([]*httpmsg.HttpRequestResponse, error) {
	if specType == Unknown {
		return nil, nil
	}

	var results []*httpmsg.HttpRequestResponse

	collect := func(rr *httpmsg.HttpRequestResponse) bool {
		if service != nil {
			rr = rr.WithService(service)
		}
		results = append(results, rr)
		return true
	}

	switch specType {
	case OpenAPI:
		opts := openapi.Options{BaseURL: baseURL, PreserveSpecServerPath: true}
		ext := openapi.DetectFormatFromContent(data)
		if err := openapi.ParseSwagger(data, ext, opts, collect); err != nil {
			return results, err
		}

	case Postman:
		f := &postman.Format{}
		if baseURL != "" {
			f.SetPostmanOptions(postman.Options{BaseURL: baseURL})
		}
		if err := f.ParseFromData(data, collect); err != nil {
			return results, err
		}

	case WSDL:
		// baseURL (the discovered service scheme+host) overrides the WSDL's own
		// <soap:address> host so generated SOAP traffic stays in scope, while the
		// address path is preserved (resolveEndpoint semantics).
		if err := wsdl.ParseData(data, wsdl.Options{EndpointURL: baseURL}, collect); err != nil {
			return results, err
		}
	}

	return results, nil
}

// ParseAndFeed detects spec type, parses endpoints, and feeds them via the feeder.
// Returns the count of endpoints fed and any error.
func ParseAndFeed(data []byte, baseURL string, service *httpmsg.Service, feeder modkit.RequestFeeder) (int, error) {
	if feeder == nil {
		return 0, nil
	}

	specType := DetectSpecType(data)
	if specType == Unknown {
		return 0, nil
	}

	var count int
	collect := func(rr *httpmsg.HttpRequestResponse) bool {
		if service != nil {
			rr = rr.WithService(service)
		}
		if feeder.Feed(rr) {
			count++
		}
		return true
	}

	switch specType {
	case OpenAPI:
		opts := openapi.Options{BaseURL: baseURL, PreserveSpecServerPath: true}
		ext := openapi.DetectFormatFromContent(data)
		if err := openapi.ParseSwagger(data, ext, opts, collect); err != nil {
			return count, err
		}
	case Postman:
		f := &postman.Format{}
		if baseURL != "" {
			f.SetPostmanOptions(postman.Options{BaseURL: baseURL})
		}
		if err := f.ParseFromData(data, collect); err != nil {
			return count, err
		}

	case WSDL:
		if err := wsdl.ParseData(data, wsdl.Options{EndpointURL: baseURL}, collect); err != nil {
			return count, err
		}
	}

	return count, nil
}

// IsSpecContentType returns true if the content-type header suggests API spec
// content. XML types are included for WSDL/SOAP descriptions; they are broad, so
// the actual gate is DetectSpecType's strict WSDL marker check — a plain XML
// response (SVG, RSS, sitemap) passes this pre-filter but resolves to Unknown
// and is dropped.
func IsSpecContentType(ct string) bool {
	ct = strings.ToLower(ct)
	for _, allowed := range []string{
		"application/json",
		"application/yaml",
		"text/yaml",
		"application/x-yaml",
		"text/json",
		"text/xml",
		"application/xml",
		"application/wsdl+xml",
		"application/soap+xml",
	} {
		if strings.HasPrefix(ct, allowed) {
			return true
		}
	}
	return false
}
