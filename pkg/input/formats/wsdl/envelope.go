package wsdl

import "strings"

// soapVersion identifies which SOAP wire format an operation uses. It is decided
// by which <soap:binding> namespace the WSDL declared (1.1 vs 1.2), which in
// turn drives the envelope namespace, the Content-Type, and whether a SOAPAction
// HTTP header is emitted.
type soapVersion int

const (
	soap11 soapVersion = iota
	soap12
)

// envelope wraps a generated body fragment (bodyXML, already indented to sit
// under <soap:Body>) in a full SOAP envelope for the given version.
func (v soapVersion) envelope(bodyXML string) string {
	envNS := nsSoapEnv11
	if v == soap12 {
		envNS = nsSoapEnv12
	}
	body := bodyXML
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	sb.WriteString(`<soapenv:Envelope xmlns:soapenv="` + envNS + `">` + "\n")
	sb.WriteString("  <soapenv:Header/>\n")
	sb.WriteString("  <soapenv:Body>\n")
	sb.WriteString(body)
	sb.WriteString("  </soapenv:Body>\n")
	sb.WriteString("</soapenv:Envelope>\n")
	return sb.String()
}

// contentType returns the request Content-Type for the version. SOAP 1.2 carries
// the action inside the media type; SOAP 1.1 carries it in a separate SOAPAction
// header (see soapActionHeader).
func (v soapVersion) contentType(action string) string {
	if v == soap12 {
		ct := `application/soap+xml; charset=utf-8`
		if action != "" {
			ct += `; action="` + action + `"`
		}
		return ct
	}
	return "text/xml; charset=utf-8"
}

// soapActionHeader returns the SOAPAction header value for SOAP 1.1 (a
// double-quoted action, empty-quoted when the operation declares none), or
// ("", false) for SOAP 1.2 where the action rides in the Content-Type instead.
func (v soapVersion) soapActionHeader(action string) (string, bool) {
	if v == soap12 {
		return "", false
	}
	return `"` + action + `"`, true
}
