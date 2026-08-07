package wsdl

import "encoding/xml"

// WSDL / SOAP namespace URIs. encoding/xml resolves element namespaces from the
// document's xmlns declarations and matches them against the URIs written
// literally in the struct tags below (Go struct tags cannot reference constants),
// so the prefix a given WSDL happens to use (tns:, wsdl:, s:, …) is irrelevant —
// only the namespace URI matters. Those namespaces are:
//
//	WSDL:      http://schemas.xmlsoap.org/wsdl/
//	SOAP 1.1:  http://schemas.xmlsoap.org/wsdl/soap/
//	SOAP 1.2:  http://schemas.xmlsoap.org/wsdl/soap12/
//	XSD:       http://www.w3.org/2001/XMLSchema
//
// The SOAP envelope namespaces below (the message wire format, distinct from the
// WSDL binding namespaces) are used in code by envelope.go.
const (
	nsSoapEnv11 = "http://schemas.xmlsoap.org/soap/envelope/"
	nsSoapEnv12 = "http://www.w3.org/2003/05/soap-envelope"
)

// definitions is the WSDL 1.1 <definitions> root document.
type definitions struct {
	XMLName         xml.Name       `xml:"http://schemas.xmlsoap.org/wsdl/ definitions"`
	TargetNamespace string         `xml:"targetNamespace,attr"`
	Types           wsdlTypes      `xml:"http://schemas.xmlsoap.org/wsdl/ types"`
	Messages        []wsdlMessage  `xml:"http://schemas.xmlsoap.org/wsdl/ message"`
	PortTypes       []wsdlPortType `xml:"http://schemas.xmlsoap.org/wsdl/ portType"`
	Bindings        []wsdlBinding  `xml:"http://schemas.xmlsoap.org/wsdl/ binding"`
	Services        []wsdlService  `xml:"http://schemas.xmlsoap.org/wsdl/ service"`
}

// wsdlTypes wraps the inline <xsd:schema> blocks used to generate sample bodies.
type wsdlTypes struct {
	Schemas []xsdSchema `xml:"http://www.w3.org/2001/XMLSchema schema"`
}

// wsdlMessage is a <message> with its <part> definitions. A part references
// either a global XSD element (document style) or a type (rpc style).
type wsdlMessage struct {
	Name  string     `xml:"name,attr"`
	Parts []wsdlPart `xml:"http://schemas.xmlsoap.org/wsdl/ part"`
}

type wsdlPart struct {
	Name    string `xml:"name,attr"`
	Element string `xml:"element,attr"` // QName of a global element (document style)
	Type    string `xml:"type,attr"`    // QName of a type (rpc style)
}

// wsdlPortType is the abstract interface: a set of operations with input/output
// messages.
type wsdlPortType struct {
	Name       string              `xml:"name,attr"`
	Operations []wsdlPortOperation `xml:"http://schemas.xmlsoap.org/wsdl/ operation"`
}

type wsdlPortOperation struct {
	Name   string        `xml:"name,attr"`
	Input  wsdlOpMessage `xml:"http://schemas.xmlsoap.org/wsdl/ input"`
	Output wsdlOpMessage `xml:"http://schemas.xmlsoap.org/wsdl/ output"`
}

type wsdlOpMessage struct {
	Name    string `xml:"name,attr"`
	Message string `xml:"message,attr"` // QName of a <message>
}

// wsdlBinding binds a portType to a concrete SOAP transport. It carries either a
// SOAP 1.1 or SOAP 1.2 <binding>; whichever is non-nil selects the wire version.
type wsdlBinding struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"` // QName of the bound <portType>

	SoapBinding11 *soapBinding        `xml:"http://schemas.xmlsoap.org/wsdl/soap/ binding"`
	SoapBinding12 *soapBinding        `xml:"http://schemas.xmlsoap.org/wsdl/soap12/ binding"`
	Operations    []wsdlBindOperation `xml:"http://schemas.xmlsoap.org/wsdl/ operation"`
}

type soapBinding struct {
	Transport string `xml:"transport,attr"`
	Style     string `xml:"style,attr"` // "document" (default) or "rpc"
}

type wsdlBindOperation struct {
	Name     string         `xml:"name,attr"`
	SoapOp11 *soapOperation `xml:"http://schemas.xmlsoap.org/wsdl/soap/ operation"`
	SoapOp12 *soapOperation `xml:"http://schemas.xmlsoap.org/wsdl/soap12/ operation"`
}

type soapOperation struct {
	SoapAction string `xml:"soapAction,attr"`
	Style      string `xml:"style,attr"` // overrides the binding-level style
}

// wsdlService groups ports; each port pins a binding to a concrete endpoint URL.
type wsdlService struct {
	Name  string     `xml:"name,attr"`
	Ports []wsdlPort `xml:"http://schemas.xmlsoap.org/wsdl/ port"`
}

type wsdlPort struct {
	Name    string `xml:"name,attr"`
	Binding string `xml:"binding,attr"` // QName of the referenced <binding>

	Address11 *soapAddress `xml:"http://schemas.xmlsoap.org/wsdl/soap/ address"`
	Address12 *soapAddress `xml:"http://schemas.xmlsoap.org/wsdl/soap12/ address"`
}

type soapAddress struct {
	Location string `xml:"location,attr"`
}

// location returns the endpoint URL of the port from whichever SOAP-version
// address element is present.
func (p wsdlPort) location() string {
	if p.Address11 != nil && p.Address11.Location != "" {
		return p.Address11.Location
	}
	if p.Address12 != nil && p.Address12.Location != "" {
		return p.Address12.Location
	}
	return ""
}
