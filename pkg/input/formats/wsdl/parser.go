package wsdl

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// ResultCallback is called for each generated HttpRequestResponse. Returning
// false stops generation.
type ResultCallback func(*httpmsg.HttpRequestResponse) bool

// ParseData parses a WSDL 1.1 document and generates one SOAP request per bound
// SOAP operation, invoking cb for each. It is best-effort: an operation that
// cannot be resolved (unknown message/portType, unbuildable body) is skipped and
// logged at debug rather than failing the whole document. A document with no
// SOAP binding at all is a hard error so the caller learns nothing was produced.
func ParseData(data []byte, opts Options, cb ResultCallback) error {
	var defs definitions
	if err := xml.Unmarshal(data, &defs); err != nil {
		return fmt.Errorf("failed to parse WSDL: %w", err)
	}
	if len(defs.Bindings) == 0 {
		return fmt.Errorf("no <binding> found in WSDL (WSDL 2.0 and unresolved multi-file imports are not supported)")
	}

	idx := buildSchemaIndex(defs.Types.Schemas)
	msgByName := indexMessages(defs.Messages)
	ptByName := indexPortTypes(defs.PortTypes)
	addrByBinding := indexEndpoints(defs.Services)

	var soapBindings int
	for bi := range defs.Bindings {
		b := &defs.Bindings[bi]
		version, ok := bindingSOAPVersion(b)
		if !ok {
			// Not a SOAP binding (e.g. an <http:binding> GET/POST binding).
			continue
		}
		soapBindings++
		defaultStyle := bindingStyle(b)

		endpoint, err := resolveEndpoint(addrByBinding[localName(b.Name)], opts.EndpointURL)
		if err != nil {
			zap.L().Debug("wsdl: skipping binding, no usable endpoint",
				zap.String("binding", b.Name), zap.Error(err))
			continue
		}

		pt := ptByName[localName(b.Type)]
		if pt == nil {
			zap.L().Debug("wsdl: binding references unknown portType",
				zap.String("binding", b.Name), zap.String("type", b.Type))
			continue
		}

		for oi := range b.Operations {
			bindOp := &b.Operations[oi]
			portOp := findPortOperation(pt, bindOp.Name)
			if portOp == nil {
				continue
			}
			inputMsg := msgByName[localName(portOp.Input.Message)]
			if inputMsg == nil {
				continue
			}

			style := operationStyle(bindOp, defaultStyle)
			action := operationSOAPAction(bindOp)
			bodyXML := buildBody(idx, style, bindOp.Name, defs.TargetNamespace, inputMsg, opts.Variables)
			if strings.TrimSpace(bodyXML) == "" {
				continue
			}

			rr, err := buildRequest(endpoint, version.envelope(bodyXML), version, action, opts.Headers)
			if err != nil {
				zap.L().Debug("wsdl: failed to build request",
					zap.String("operation", bindOp.Name), zap.Error(err))
				continue
			}
			if !cb(rr) {
				return nil
			}
		}
	}

	if soapBindings == 0 {
		return fmt.Errorf("no SOAP binding found in WSDL (only non-SOAP transports declared)")
	}
	return nil
}

// CountOperations returns the number of bound SOAP operations in the WSDL, used
// by the FileSource pre-count. Parse errors surface as (0, err).
func CountOperations(data []byte) (int64, error) {
	var defs definitions
	if err := xml.Unmarshal(data, &defs); err != nil {
		return 0, fmt.Errorf("failed to parse WSDL: %w", err)
	}
	var count int64
	for bi := range defs.Bindings {
		b := &defs.Bindings[bi]
		if _, ok := bindingSOAPVersion(b); !ok {
			continue
		}
		count += int64(len(b.Operations))
	}
	return count, nil
}

func indexMessages(msgs []wsdlMessage) map[string]*wsdlMessage {
	m := make(map[string]*wsdlMessage, len(msgs))
	for i := range msgs {
		m[msgs[i].Name] = &msgs[i]
	}
	return m
}

func indexPortTypes(pts []wsdlPortType) map[string]*wsdlPortType {
	m := make(map[string]*wsdlPortType, len(pts))
	for i := range pts {
		m[pts[i].Name] = &pts[i]
	}
	return m
}

// indexEndpoints maps each binding's local name to the first port endpoint URL
// that references it.
func indexEndpoints(services []wsdlService) map[string]string {
	m := map[string]string{}
	for _, svc := range services {
		for _, port := range svc.Ports {
			loc := port.location()
			if loc == "" {
				continue
			}
			bl := localName(port.Binding)
			if _, exists := m[bl]; !exists {
				m[bl] = loc
			}
		}
	}
	return m
}

// bindingSOAPVersion reports the SOAP version of a binding, or false when the
// binding is not a SOAP binding at all.
func bindingSOAPVersion(b *wsdlBinding) (soapVersion, bool) {
	if b.SoapBinding12 != nil {
		return soap12, true
	}
	if b.SoapBinding11 != nil {
		return soap11, true
	}
	return soap11, false
}

func bindingStyle(b *wsdlBinding) string {
	if b.SoapBinding12 != nil && b.SoapBinding12.Style != "" {
		return b.SoapBinding12.Style
	}
	if b.SoapBinding11 != nil && b.SoapBinding11.Style != "" {
		return b.SoapBinding11.Style
	}
	return "document"
}

func operationStyle(op *wsdlBindOperation, def string) string {
	if op.SoapOp12 != nil && op.SoapOp12.Style != "" {
		return op.SoapOp12.Style
	}
	if op.SoapOp11 != nil && op.SoapOp11.Style != "" {
		return op.SoapOp11.Style
	}
	return def
}

func operationSOAPAction(op *wsdlBindOperation) string {
	if op.SoapOp12 != nil {
		return op.SoapOp12.SoapAction
	}
	if op.SoapOp11 != nil {
		return op.SoapOp11.SoapAction
	}
	return ""
}

func findPortOperation(pt *wsdlPortType, name string) *wsdlPortOperation {
	for i := range pt.Operations {
		if pt.Operations[i].Name == name {
			return &pt.Operations[i]
		}
	}
	return nil
}

// buildBody renders the SOAP body fragment for an operation. Document style puts
// the message part's global element directly under <soap:Body>; rpc style wraps
// the parts in an operation-named element in the definitions targetNamespace.
func buildBody(idx *schemaIndex, style, opName, tns string, msg *wsdlMessage, vars map[string]string) string {
	if strings.EqualFold(style, "rpc") {
		return buildRPCBody(idx, opName, tns, msg, vars)
	}
	// Document style: the first part that references a global element is the body
	// root.
	for _, part := range msg.Parts {
		if part.Element != "" {
			if body := idx.generateElementBody(localName(part.Element), vars, 4); body != "" {
				return body
			}
		}
	}
	// A document-style message whose part uses type= (unusual) still yields a
	// body via the rpc wrapper so the operation isn't dropped.
	return buildRPCBody(idx, opName, tns, msg, vars)
}

// buildRPCBody wraps each message part in the operation element, namespaced to
// the definitions targetNamespace (rpc/literal convention).
func buildRPCBody(idx *schemaIndex, opName, tns string, msg *wsdlMessage, vars map[string]string) string {
	var inner strings.Builder
	for _, part := range msg.Parts {
		if part.Name == "" && part.Element == "" {
			continue
		}
		if part.Type == "" && part.Element != "" {
			if body := idx.generateElementBody(localName(part.Element), vars, 6); body != "" {
				inner.WriteString(body)
				continue
			}
		}
		typeQName := part.Type
		if typeQName == "" {
			typeQName = "string"
		}
		inner.WriteString(idx.generateSyntheticElement(part.Name, typeQName, "", vars, 6))
	}
	if strings.TrimSpace(inner.String()) == "" {
		return ""
	}
	ns := ""
	if tns != "" {
		ns = ` xmlns="` + tns + `"`
	}
	return "    <" + opName + ns + ">\n" + inner.String() + "    </" + opName + ">\n"
}

// buildRequest assembles the POST request for one operation and converts it to
// the internal HttpRequestResponse model.
func buildRequest(endpoint, envelope string, version soapVersion, action string, headers map[string]string) (*httpmsg.HttpRequestResponse, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader([]byte(envelope)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", version.contentType(action))
	if hv, ok := version.soapActionHeader(action); ok {
		// Assign the map key directly to preserve exact "SOAPAction" casing.
		// http.Header.Set would canonicalize it to "Soapaction", which some picky
		// SOAP 1.1 stacks reject; DumpRequestOut (in FromStdRequest) writes map
		// keys verbatim, so the exact casing survives to the wire.
		req.Header["SOAPAction"] = []string{hv}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return httpmsg.FromStdRequest(req)
}

// resolveEndpoint combines the WSDL-declared address with an optional override.
// Mirrors openapi BaseURL semantics: when override is a usable absolute URL its
// scheme+host win (enforcing the in-scope target host) while the WSDL address
// path+query are preserved; when the WSDL has no address, the override is used
// verbatim. An empty result is an error so the operation is skipped rather than
// POSTing to nowhere.
func resolveEndpoint(wsdlAddr, override string) (string, error) {
	override = strings.TrimSpace(override)
	wsdlAddr = strings.TrimSpace(wsdlAddr)
	if override == "" {
		if wsdlAddr == "" {
			return "", fmt.Errorf("no <soap:address> in WSDL and no endpoint override")
		}
		return wsdlAddr, nil
	}
	ov, err := url.Parse(override)
	if err != nil || ov.Scheme == "" || ov.Host == "" {
		// Override isn't a usable absolute URL; prefer the WSDL address, else the
		// raw override.
		if wsdlAddr != "" {
			return wsdlAddr, nil
		}
		return override, nil
	}
	if wsdlAddr == "" {
		return override, nil
	}
	wa, err := url.Parse(wsdlAddr)
	if err != nil || wa.Path == "" {
		return ov.String(), nil
	}
	ov.Path = wa.Path
	ov.RawQuery = wa.RawQuery
	return ov.String(), nil
}
