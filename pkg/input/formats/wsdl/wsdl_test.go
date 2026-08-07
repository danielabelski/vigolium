package wsdl

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// calcWSDL is a neutral ASMX-style WSDL declaring both a SOAP 1.1 and a SOAP 1.2
// binding for a single document/literal operation. Host is example.com.
const calcWSDL = `<?xml version="1.0" encoding="utf-8"?>
<wsdl:definitions xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:tns="http://tempuri.org/" xmlns:s="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/" xmlns:http="http://schemas.xmlsoap.org/wsdl/http/" targetNamespace="http://tempuri.org/" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
  <wsdl:types>
    <s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
      <s:element name="Add">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="1" name="intA" type="s:int"/>
            <s:element minOccurs="1" maxOccurs="1" name="intB" type="s:int"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="AddResponse">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="1" name="AddResult" type="s:int"/>
          </s:sequence>
        </s:complexType>
      </s:element>
    </s:schema>
  </wsdl:types>
  <wsdl:message name="AddSoapIn"><wsdl:part name="parameters" element="tns:Add"/></wsdl:message>
  <wsdl:message name="AddSoapOut"><wsdl:part name="parameters" element="tns:AddResponse"/></wsdl:message>
  <wsdl:portType name="CalculatorSoap">
    <wsdl:operation name="Add">
      <wsdl:input message="tns:AddSoapIn"/>
      <wsdl:output message="tns:AddSoapOut"/>
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="CalculatorSoap" type="tns:CalculatorSoap">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="Add">
      <soap:operation soapAction="http://tempuri.org/Add" style="document"/>
      <wsdl:input><soap:body use="literal"/></wsdl:input>
      <wsdl:output><soap:body use="literal"/></wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:binding name="CalculatorSoap12" type="tns:CalculatorSoap">
    <soap12:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="Add">
      <soap12:operation soapAction="http://tempuri.org/Add" style="document"/>
      <wsdl:input><soap12:body use="literal"/></wsdl:input>
      <wsdl:output><soap12:body use="literal"/></wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="Calculator">
    <wsdl:port name="CalculatorSoap" binding="tns:CalculatorSoap">
      <soap:address location="http://www.example.com/calculator.asmx"/>
    </wsdl:port>
    <wsdl:port name="CalculatorSoap12" binding="tns:CalculatorSoap12">
      <soap12:address location="http://www.example.com/calculator.asmx"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>`

func collect(t *testing.T, data string, opts Options) []*httpmsg.HttpRequestResponse {
	t.Helper()
	var out []*httpmsg.HttpRequestResponse
	err := ParseData([]byte(data), opts, func(rr *httpmsg.HttpRequestResponse) bool {
		out = append(out, rr)
		return true
	})
	if err != nil {
		t.Fatalf("ParseData error: %v", err)
	}
	return out
}

func TestParseDocumentLiteralBothSOAPVersions(t *testing.T) {
	reqs := collect(t, calcWSDL, Options{})
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests (SOAP 1.1 + 1.2 bindings), got %d", len(reqs))
	}

	var raw11, raw12 string
	for _, rr := range reqs {
		raw := string(rr.Request().Raw())
		if strings.Contains(raw, "application/soap+xml") {
			raw12 = raw
		} else {
			raw11 = raw
		}
	}
	if raw11 == "" || raw12 == "" {
		t.Fatalf("expected one SOAP 1.1 and one SOAP 1.2 request\n1.1=%q\n1.2=%q", raw11, raw12)
	}

	// Both must be POSTs to the WSDL-declared endpoint path with the synthesized body.
	for _, raw := range []string{raw11, raw12} {
		if !strings.HasPrefix(raw, "POST /calculator.asmx ") {
			t.Errorf("expected POST to /calculator.asmx, got start: %q", firstLine(raw))
		}
		if !strings.Contains(raw, `<Add xmlns="http://tempuri.org/">`) {
			t.Errorf("body missing operation element with target namespace:\n%s", raw)
		}
		if !strings.Contains(raw, "<intA>0</intA>") || !strings.Contains(raw, "<intB>0</intB>") {
			t.Errorf("body missing synthesized int params:\n%s", raw)
		}
	}

	// SOAP 1.1: text/xml + quoted SOAPAction header; SOAP 1.2: action in content-type, no SOAPAction.
	if !strings.Contains(raw11, "Content-Type: text/xml") {
		t.Errorf("SOAP 1.1 wrong content-type:\n%s", raw11)
	}
	if !strings.Contains(raw11, `SOAPAction: "http://tempuri.org/Add"`) {
		t.Errorf("SOAP 1.1 missing SOAPAction header:\n%s", raw11)
	}
	if !strings.Contains(raw11, nsSoapEnv11) {
		t.Errorf("SOAP 1.1 wrong envelope namespace:\n%s", raw11)
	}
	if !strings.Contains(raw12, `action="http://tempuri.org/Add"`) {
		t.Errorf("SOAP 1.2 missing action in content-type:\n%s", raw12)
	}
	if strings.Contains(raw12, "SOAPAction:") {
		t.Errorf("SOAP 1.2 must not carry a SOAPAction header:\n%s", raw12)
	}
	if !strings.Contains(raw12, nsSoapEnv12) {
		t.Errorf("SOAP 1.2 wrong envelope namespace:\n%s", raw12)
	}
}

func TestEndpointOverridePreservesPath(t *testing.T) {
	reqs := collect(t, calcWSDL, Options{EndpointURL: "https://target.internal"})
	if len(reqs) == 0 {
		t.Fatal("no requests generated")
	}
	raw := string(reqs[0].Request().Raw())
	if !strings.Contains(raw, "Host: target.internal") {
		t.Errorf("override host not applied:\n%s", raw)
	}
	if !strings.HasPrefix(raw, "POST /calculator.asmx ") {
		t.Errorf("WSDL path not preserved under override: %q", firstLine(raw))
	}
}

func TestVariableOverride(t *testing.T) {
	reqs := collect(t, calcWSDL, Options{Variables: map[string]string{"intA": "1337"}})
	raw := string(reqs[0].Request().Raw())
	if !strings.Contains(raw, "<intA>1337</intA>") {
		t.Errorf("variable override not applied:\n%s", raw)
	}
}

func TestCountOperations(t *testing.T) {
	n, err := CountOperations([]byte(calcWSDL))
	if err != nil {
		t.Fatalf("CountOperations error: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 operations, got %d", n)
	}
}

func TestIsWSDL(t *testing.T) {
	if !IsWSDL([]byte(calcWSDL)) {
		t.Error("calcWSDL should be detected as WSDL")
	}
	// Plain XSD / arbitrary XML must not be misclassified.
	if IsWSDL([]byte(`<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>`)) {
		t.Error("RSS should not be detected as WSDL")
	}
	if IsWSDL([]byte(`<s:schema xmlns:s="http://www.w3.org/2001/XMLSchema"></s:schema>`)) {
		t.Error("bare XSD schema should not be detected as WSDL")
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// rpcWSDL exercises the rpc-style path: message parts reference types (not global
// elements) and the body wraps them in an operation-named element.
const rpcWSDL = `<?xml version="1.0" encoding="utf-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:tns="http://example.org/calc" xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://example.org/calc">
  <message name="AddIn">
    <part name="a" type="xsd:int"/>
    <part name="b" type="xsd:int"/>
  </message>
  <portType name="CalcPort">
    <operation name="Add"><input message="tns:AddIn"/></operation>
  </portType>
  <binding name="CalcBinding" type="tns:CalcPort">
    <soap:binding style="rpc" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="Add">
      <soap:operation soapAction="urn:Add"/>
      <input><soap:body use="literal"/></input>
    </operation>
  </binding>
  <service name="CalcService">
    <port name="CalcPort" binding="tns:CalcBinding">
      <soap:address location="http://calc.example.org/soap"/>
    </port>
  </service>
</definitions>`

func TestParseRPCStyle(t *testing.T) {
	reqs := collect(t, rpcWSDL, Options{})
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	raw := string(reqs[0].Request().Raw())
	if !strings.HasPrefix(raw, "POST /soap ") {
		t.Errorf("expected POST /soap, got: %q", firstLine(raw))
	}
	if !strings.Contains(raw, `<Add xmlns="http://example.org/calc">`) {
		t.Errorf("rpc body missing operation wrapper:\n%s", raw)
	}
	if !strings.Contains(raw, "<a>0</a>") || !strings.Contains(raw, "<b>0</b>") {
		t.Errorf("rpc body missing part elements:\n%s", raw)
	}
	if !strings.Contains(raw, `SOAPAction: "urn:Add"`) {
		t.Errorf("missing SOAPAction:\n%s", raw)
	}
}

func TestNormalizeServiceURL(t *testing.T) {
	cases := map[string]string{
		"https://h/Service.svc":            "https://h/Service.svc?singleWsdl",
		"https://h/Service.asmx":           "https://h/Service.asmx?WSDL",
		"https://h/Service.svc?wsdl":       "https://h/Service.svc?wsdl", // already a wsdl query
		"https://h/Service.svc?singleWsdl": "https://h/Service.svc?singleWsdl",
		"https://h/spec.wsdl":              "https://h/spec.wsdl", // plain file, untouched
	}
	for in, want := range cases {
		if got := normalizeServiceURL(in); got != want {
			t.Errorf("normalizeServiceURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNoSOAPBindingErrors(t *testing.T) {
	// A WSDL whose only binding is a non-SOAP <http:binding> must error, not
	// silently produce zero requests.
	httpOnly := `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:http="http://schemas.xmlsoap.org/wsdl/http/" xmlns:tns="urn:x" targetNamespace="urn:x">
  <portType name="P"><operation name="Op"/></portType>
  <binding name="B" type="tns:P"><http:binding verb="GET"/><operation name="Op"/></binding>
</definitions>`
	err := ParseData([]byte(httpOnly), Options{}, func(*httpmsg.HttpRequestResponse) bool { return true })
	if err == nil {
		t.Error("expected error for WSDL with no SOAP binding, got nil")
	}
}
