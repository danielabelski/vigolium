package curl

import "time"

// TransportHints carries the curl options that describe *how* to send a
// request rather than what the request bytes are. The parser can't act on
// them — an HttpRequestResponse has no room for a proxy or a client cert — so
// they're handed back to the caller, which decides whether to honor them.
//
// Zero values mean "the command didn't say"; a caller's own explicit flags
// should win over anything here.
type TransportHints struct {
	Proxy     string // -x/--proxy
	ProxyUser string // -U/--proxy-user

	Insecure   bool // -k/--insecure
	Compressed bool // --compressed
	Location   bool // -L/--location (curl's default is NOT to follow)
	MaxRedirs  int  // --max-redirs
	PathAsIs   bool // --path-as-is

	ConnectTimeout time.Duration // --connect-timeout
	MaxTime        time.Duration // -m/--max-time
	Retry          int           // --retry
	RetryDelay     time.Duration // --retry-delay

	Resolve   []string // --resolve host:port:addr (repeatable)
	ConnectTo []string // --connect-to (repeatable)

	ClientCert string // -E/--cert
	ClientKey  string // --key
	CACert     string // --cacert

	HTTPVersion string // "1.0" | "1.1" | "2" | "3"
	Interface   string // --interface
	UnixSocket  string // --unix-socket
}

// IsZero reports whether the command carried no transport options at all.
func (h TransportHints) IsZero() bool {
	return h.Proxy == "" && h.ProxyUser == "" && !h.Insecure && !h.Compressed &&
		!h.Location && h.MaxRedirs == 0 && !h.PathAsIs &&
		h.ConnectTimeout == 0 && h.MaxTime == 0 && h.Retry == 0 && h.RetryDelay == 0 &&
		len(h.Resolve) == 0 && len(h.ConnectTo) == 0 &&
		h.ClientCert == "" && h.ClientKey == "" && h.CACert == "" &&
		h.HTTPVersion == "" && h.Interface == "" && h.UnixSocket == ""
}
