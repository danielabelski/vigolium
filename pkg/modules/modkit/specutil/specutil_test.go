package specutil

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestDetectSpecType_OpenAPI(t *testing.T) {
	data := []byte(`{"swagger": "2.0", "info": {"title": "Test"}, "paths": {}}`)
	if got := DetectSpecType(data); got != OpenAPI {
		t.Errorf("DetectSpecType(swagger json) = %d, want OpenAPI (%d)", got, OpenAPI)
	}

	yamlData := []byte("swagger: \"2.0\"\ninfo:\n  title: Test\npaths: {}\n")
	if got := DetectSpecType(yamlData); got != OpenAPI {
		t.Errorf("DetectSpecType(swagger yaml) = %d, want OpenAPI (%d)", got, OpenAPI)
	}
}

func TestDetectSpecType_Postman(t *testing.T) {
	data := []byte(`{"info": {"_postman_id": "abc123", "name": "Test"}, "item": []}`)
	if got := DetectSpecType(data); got != Postman {
		t.Errorf("DetectSpecType(postman) = %d, want Postman (%d)", got, Postman)
	}

	data2 := []byte(`{"info": {"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, "item": []}`)
	if got := DetectSpecType(data2); got != Postman {
		t.Errorf("DetectSpecType(postman schema) = %d, want Postman (%d)", got, Postman)
	}
}

func TestDetectSpecType_Unknown(t *testing.T) {
	data := []byte(`{"name": "not a spec"}`)
	if got := DetectSpecType(data); got != Unknown {
		t.Errorf("DetectSpecType(unknown) = %d, want Unknown (%d)", got, Unknown)
	}
}

func TestIsSpecContentType(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/yaml", true},
		{"text/yaml", true},
		{"application/x-yaml", true},
		{"text/json", true},
		{"text/html", false},
		{"image/png", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsSpecContentType(tt.ct); got != tt.want {
			t.Errorf("IsSpecContentType(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}

// mockFeeder collects fed requests for testing.
type mockFeeder struct {
	items []*httpmsg.HttpRequestResponse
}

func (f *mockFeeder) Feed(rr *httpmsg.HttpRequestResponse) bool {
	f.items = append(f.items, rr)
	return true
}

var _ modkit.RequestFeeder = (*mockFeeder)(nil)

func TestParseAndFeed_OpenAPISwagger(t *testing.T) {
	spec := []byte(`swagger: "2.0"
info:
  title: Test API
  version: "1.0"
host: example.com
basePath: /v1
schemes:
  - https
paths:
  /users:
    get:
      summary: Get users
      responses:
        200:
          description: OK
  /items:
    post:
      summary: Create item
      responses:
        201:
          description: Created
`)

	feeder := &mockFeeder{}
	service := httpmsg.NewServiceSecure("example.com", 443, true)

	count, err := ParseAndFeed(spec, "https://example.com", service, feeder)
	if err != nil {
		t.Fatalf("ParseAndFeed() error = %v", err)
	}
	if count == 0 {
		t.Fatal("ParseAndFeed() returned 0 endpoints, expected > 0")
	}
	if len(feeder.items) != count {
		t.Errorf("feeder received %d items, count returned %d", len(feeder.items), count)
	}
}

func TestParseAndFeed_NilFeeder(t *testing.T) {
	spec := []byte(`{"swagger": "2.0", "info": {"title": "Test"}, "paths": {"/a": {"get": {}}}}`)
	count, err := ParseAndFeed(spec, "https://example.com", nil, nil)
	if err != nil {
		t.Fatalf("ParseAndFeed() error = %v", err)
	}
	if count != 0 {
		t.Errorf("ParseAndFeed(nil feeder) = %d, want 0", count)
	}
}

func TestParseAndFeed_UnknownSpec(t *testing.T) {
	data := []byte(`{"not": "a spec"}`)
	feeder := &mockFeeder{}
	count, err := ParseAndFeed(data, "", nil, feeder)
	if err != nil {
		t.Fatalf("ParseAndFeed() error = %v", err)
	}
	if count != 0 {
		t.Errorf("ParseAndFeed(unknown) = %d, want 0", count)
	}
}

func TestParseSpec_OpenAPI(t *testing.T) {
	spec := []byte(`swagger: "2.0"
info:
  title: Test API
  version: "1.0"
host: example.com
basePath: /v1
schemes:
  - https
paths:
  /users:
    get:
      summary: Get users
      responses:
        200:
          description: OK
  /items:
    post:
      summary: Create item
      responses:
        201:
          description: Created
`)

	service := httpmsg.NewServiceSecure("example.com", 443, true)
	endpoints, err := ParseSpec(spec, "https://example.com", service)
	if err != nil {
		t.Fatalf("ParseSpec() error = %v", err)
	}
	if len(endpoints) == 0 {
		t.Fatal("ParseSpec() returned 0 endpoints, expected > 0")
	}
	// Each endpoint should have service set
	for i, rr := range endpoints {
		if rr.Service() == nil {
			t.Errorf("endpoint %d has nil service", i)
		}
	}
}

func TestParseSpec_Unknown(t *testing.T) {
	data := []byte(`{"not": "a spec"}`)
	endpoints, err := ParseSpec(data, "", nil)
	if err != nil {
		t.Fatalf("ParseSpec() error = %v", err)
	}
	if len(endpoints) != 0 {
		t.Errorf("ParseSpec(unknown) returned %d endpoints, want 0", len(endpoints))
	}
}

// minimalWSDL is a compact document/literal SOAP 1.1 service (host example.com)
// used to exercise the WSDL branch of the spec auto-ingest path.
const minimalWSDL = `<?xml version="1.0" encoding="utf-8"?>
<wsdl:definitions xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:tns="http://tempuri.org/" xmlns:s="http://www.w3.org/2001/XMLSchema" targetNamespace="http://tempuri.org/" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
  <wsdl:types>
    <s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
      <s:element name="Echo"><s:complexType><s:sequence>
        <s:element minOccurs="0" maxOccurs="1" name="msg" type="s:string"/>
      </s:sequence></s:complexType></s:element>
    </s:schema>
  </wsdl:types>
  <wsdl:message name="EchoIn"><wsdl:part name="parameters" element="tns:Echo"/></wsdl:message>
  <wsdl:portType name="SvcSoap">
    <wsdl:operation name="Echo"><wsdl:input message="tns:EchoIn"/></wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="SvcSoap" type="tns:SvcSoap">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="Echo">
      <soap:operation soapAction="http://tempuri.org/Echo" style="document"/>
      <wsdl:input><soap:body use="literal"/></wsdl:input>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="Svc">
    <wsdl:port name="SvcSoap" binding="tns:SvcSoap">
      <soap:address location="http://www.example.com/svc.asmx"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>`

func TestDetectSpecType_WSDL(t *testing.T) {
	if got := DetectSpecType([]byte(minimalWSDL)); got != WSDL {
		t.Errorf("DetectSpecType(wsdl) = %d, want WSDL (%d)", got, WSDL)
	}
	// A non-WSDL XML response must not be misclassified as a spec.
	if got := DetectSpecType([]byte(`<?xml version="1.0"?><urlset><url><loc>x</loc></url></urlset>`)); got != Unknown {
		t.Errorf("DetectSpecType(sitemap xml) = %d, want Unknown", got)
	}
}

func TestParseSpecTyped_WSDL_HostOverride(t *testing.T) {
	svc, err := httpmsg.ParseService("https://target.internal")
	if err != nil {
		t.Fatalf("ParseService: %v", err)
	}
	// baseURL (discovered service host) overrides the WSDL's example.com address.
	endpoints, err := ParseSpecTyped(WSDL, []byte(minimalWSDL), "https://target.internal", svc)
	if err != nil {
		t.Fatalf("ParseSpecTyped(WSDL): %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 generated SOAP request, got %d", len(endpoints))
	}
	raw := string(endpoints[0].Request().Raw())
	if !strings.Contains(raw, "POST /svc.asmx ") {
		t.Errorf("expected POST to WSDL path /svc.asmx, got: %q", raw)
	}
	if !strings.Contains(raw, "Host: target.internal") {
		t.Errorf("host override not applied:\n%s", raw)
	}
	if !strings.Contains(raw, "<Echo") {
		t.Errorf("SOAP body missing operation element:\n%s", raw)
	}
}

func TestIsSpecContentType_XML(t *testing.T) {
	for _, ct := range []string{"text/xml", "application/xml; charset=utf-8", "application/wsdl+xml", "application/soap+xml"} {
		if !IsSpecContentType(ct) {
			t.Errorf("IsSpecContentType(%q) = false, want true", ct)
		}
	}
	if IsSpecContentType("image/png") {
		t.Error("IsSpecContentType(image/png) = true, want false")
	}
}
