package wsdl

import (
	"bytes"
	"os"
)

// sniffLimit bounds how many bytes SniffFile reads — a WSDL's <definitions> root
// and its namespace declarations sit at the very top of the document.
const sniffLimit = 64 * 1024

// IsWSDL reports whether data looks like a SOAP WSDL 1.1 document: a
// <definitions> root together with the WSDL namespace AND a SOAP binding
// namespace. Requiring all three keeps arbitrary XML (SVG, RSS, sitemaps, SAML,
// plain XSD) from being misclassified, and excludes WSDLs that only declare a
// non-SOAP <http:binding> — which this parser can't turn into SOAP traffic.
func IsWSDL(data []byte) bool {
	return bytes.Contains(data, []byte("definitions")) &&
		bytes.Contains(data, []byte("schemas.xmlsoap.org/wsdl/")) &&
		bytes.Contains(data, []byte("schemas.xmlsoap.org/wsdl/soap"))
}

// SniffFile reads the head of a file and reports whether it looks like a WSDL.
// Used to auto-detect a WSDL passed without an explicit -I wsdl (mirrors
// burpscope.SniffFile). Returns false on any read error.
func SniffFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, sniffLimit)
	n, _ := f.Read(buf)
	return IsWSDL(buf[:n])
}
