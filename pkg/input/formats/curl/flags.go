package curl

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// curlFlag describes one curl option: whether it consumes a following argument
// and what the parser does with it. A nil apply means "recognized, deliberately
// irrelevant to the request we reconstruct" (e.g. -s/--silent) — the flag and
// its argument are consumed and dropped.
//
// The table is the single source of truth for arg-consumption. Anything not in
// it is an error rather than a silent skip: curl's own convention is that an
// unknown flag's *value* is a bare token, and skipping only the flag makes that
// value look like the URL. That mistake silently retargets the request (a
// `-e https://referer/` would have us fuzz the referer's host), which is far
// worse than refusing to guess.
type curlFlag struct {
	arg   bool
	apply func(s *curlSpec, v string) error
}

// ignored marks a flag as recognized-but-irrelevant; arg says whether it still
// consumes the next token.
func ignored(arg bool) curlFlag { return curlFlag{arg: arg} }

// shortFlags maps single-character curl options. Short flags cluster
// (`-sSL`), and an arg-taking short may carry its value attached (`-XPOST`,
// `-H'A: b'`), so this table is consulted per character.
var shortFlags = map[byte]curlFlag{
	// Request shape.
	'X': {arg: true, apply: func(s *curlSpec, v string) error { s.setMethod(v); return nil }},
	'H': {arg: true, apply: func(s *curlSpec, v string) error { return s.addHeader(v) }},
	'd': {arg: true, apply: func(s *curlSpec, v string) error { s.addData(v, DataAscii); return nil }},
	'F': {arg: true, apply: func(s *curlSpec, v string) error { s.forms = append(s.forms, v); return nil }},
	'T': {arg: true, apply: func(s *curlSpec, v string) error { s.uploadFile = v; return nil }},
	'G': {apply: func(s *curlSpec, _ string) error { s.asGet = true; return nil }},
	'I': {apply: func(s *curlSpec, _ string) error { s.asHead = true; return nil }},

	// Identity.
	'b': {arg: true, apply: func(s *curlSpec, v string) error { s.addCookie(v); return nil }},
	'u': {arg: true, apply: func(s *curlSpec, v string) error { s.basicAuth = v; return nil }},
	'A': {arg: true, apply: func(s *curlSpec, v string) error { s.userAgent = v; return nil }},
	'e': {arg: true, apply: func(s *curlSpec, v string) error { s.referer = v; return nil }},

	// Transport — captured as hints, not part of the request bytes.
	'x': {arg: true, apply: func(s *curlSpec, v string) error { s.hints.Proxy = v; return nil }},
	'U': {arg: true, apply: func(s *curlSpec, v string) error { s.hints.ProxyUser = v; return nil }},
	'E': {arg: true, apply: func(s *curlSpec, v string) error { s.hints.ClientCert = v; return nil }},
	'm': {arg: true, apply: func(s *curlSpec, v string) error { return s.setSeconds(&s.hints.MaxTime, v, "-m") }},
	'k': {apply: func(s *curlSpec, _ string) error { s.hints.Insecure = true; return nil }},
	'L': {apply: func(s *curlSpec, _ string) error { s.hints.Location = true; return nil }},
	'0': {apply: func(s *curlSpec, _ string) error { s.hints.HTTPVersion = "1.0"; return nil }},

	// Recognized, irrelevant to the reconstructed request.
	'c': ignored(true),  // --cookie-jar
	'o': ignored(true),  // --output
	'w': ignored(true),  // --write-out
	'D': ignored(true),  // --dump-header
	'C': ignored(true),  // --continue-at
	'r': ignored(true),  // --range
	'y': ignored(true),  // --speed-time
	'Y': ignored(true),  // --speed-limit
	'z': ignored(true),  // --time-cond
	'K': ignored(true),  // --config
	'Q': ignored(true),  // --quote
	'P': ignored(true),  // --ftp-port
	's': ignored(false), // --silent
	'S': ignored(false), // --show-error
	'v': ignored(false), // --verbose
	'f': ignored(false), // --fail
	'g': ignored(false), // --globoff
	'i': ignored(false), // --include
	'j': ignored(false), // --junk-session-cookies
	'J': ignored(false), // --remote-header-name
	'n': ignored(false), // --netrc
	'N': ignored(false), // --no-buffer
	'O': ignored(false), // --remote-name
	'p': ignored(false), // --proxytunnel
	'q': ignored(false), // --disable
	'R': ignored(false), // --remote-time
	'a': ignored(false), // --append
	'l': ignored(false), // --list-only
	'M': ignored(false), // --manual
	'V': ignored(false), // --version
	'h': ignored(false), // --help
	'#': ignored(false), // --progress-bar
	'1': ignored(false), // --tlsv1
	'2': ignored(false), // --sslv2
	'3': ignored(false), // --sslv3
	'4': ignored(false), // --ipv4
	'6': ignored(false), // --ipv6
}

// longFlags maps curl's long options. Values may be attached with '=' as well
// as space-separated; the parser splits on '=' before lookup.
var longFlags = map[string]curlFlag{
	// Request shape.
	"request":    shortFlags['X'],
	"header":     shortFlags['H'],
	"data":       shortFlags['d'],
	"data-ascii": shortFlags['d'],
	"data-raw": {arg: true, apply: func(s *curlSpec, v string) error {
		s.addData(v, DataRaw)
		return nil
	}},
	"data-binary": {arg: true, apply: func(s *curlSpec, v string) error {
		s.addData(v, DataBinary)
		return nil
	}},
	"data-urlencode": {arg: true, apply: func(s *curlSpec, v string) error {
		s.addData(v, DataURLEncode)
		return nil
	}},
	"json": {arg: true, apply: func(s *curlSpec, v string) error {
		s.jsonShorthand = true
		s.addData(v, DataRaw)
		return nil
	}},
	"form":        shortFlags['F'],
	"form-string": {arg: true, apply: func(s *curlSpec, v string) error { s.formStrings = append(s.formStrings, v); return nil }},
	"upload-file": shortFlags['T'],
	"get":         shortFlags['G'],
	"head":        shortFlags['I'],
	"url": {arg: true, apply: func(s *curlSpec, v string) error {
		return s.setURL(v, "--url")
	}},

	// Identity.
	"cookie":     shortFlags['b'],
	"user":       shortFlags['u'],
	"user-agent": shortFlags['A'],
	"referer":    shortFlags['e'],
	"oauth2-bearer": {arg: true, apply: func(s *curlSpec, v string) error {
		s.bearer = v
		return nil
	}},

	// Transport hints.
	"proxy":      shortFlags['x'],
	"proxy-user": shortFlags['U'],
	"cert":       shortFlags['E'],
	"key":        {arg: true, apply: func(s *curlSpec, v string) error { s.hints.ClientKey = v; return nil }},
	"cacert":     {arg: true, apply: func(s *curlSpec, v string) error { s.hints.CACert = v; return nil }},
	"insecure":   shortFlags['k'],
	"location":   shortFlags['L'],
	"location-trusted": {apply: func(s *curlSpec, _ string) error {
		s.hints.Location = true
		return nil
	}},
	"max-time": shortFlags['m'],
	"connect-timeout": {arg: true, apply: func(s *curlSpec, v string) error {
		return s.setSeconds(&s.hints.ConnectTimeout, v, "--connect-timeout")
	}},
	"max-redirs": {arg: true, apply: func(s *curlSpec, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("--max-redirs %q: want an integer", v)
		}
		s.hints.MaxRedirs = n
		return nil
	}},
	"resolve": {arg: true, apply: func(s *curlSpec, v string) error {
		s.hints.Resolve = append(s.hints.Resolve, v)
		return nil
	}},
	"connect-to": {arg: true, apply: func(s *curlSpec, v string) error {
		s.hints.ConnectTo = append(s.hints.ConnectTo, v)
		return nil
	}},
	"unix-socket": {arg: true, apply: func(s *curlSpec, v string) error { s.hints.UnixSocket = v; return nil }},
	"interface":   {arg: true, apply: func(s *curlSpec, v string) error { s.hints.Interface = v; return nil }},
	"compressed":  {apply: func(s *curlSpec, _ string) error { s.hints.Compressed = true; return nil }},
	"path-as-is":  {apply: func(s *curlSpec, _ string) error { s.hints.PathAsIs = true; return nil }},
	"http1.0":     shortFlags['0'],
	"http1.1":     {apply: func(s *curlSpec, _ string) error { s.hints.HTTPVersion = "1.1"; return nil }},
	"http2":       {apply: func(s *curlSpec, _ string) error { s.hints.HTTPVersion = "2"; return nil }},
	"http2-prior-knowledge": {apply: func(s *curlSpec, _ string) error {
		s.hints.HTTPVersion = "2"
		return nil
	}},
	"http3": {apply: func(s *curlSpec, _ string) error { s.hints.HTTPVersion = "3"; return nil }},
	"retry": {arg: true, apply: func(s *curlSpec, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("--retry %q: want an integer", v)
		}
		s.hints.Retry = n
		return nil
	}},
	"retry-delay": {arg: true, apply: func(s *curlSpec, v string) error {
		return s.setSeconds(&s.hints.RetryDelay, v, "--retry-delay")
	}},

	// Recognized, irrelevant.
	"silent": ignored(false), "show-error": ignored(false), "verbose": ignored(false),
	"fail": ignored(false), "fail-with-body": ignored(false), "fail-early": ignored(false),
	"globoff": ignored(false), "include": ignored(false), "no-buffer": ignored(false),
	"remote-name": ignored(false), "remote-header-name": ignored(false),
	"remote-time": ignored(false), "create-dirs": ignored(false), "append": ignored(false),
	"junk-session-cookies": ignored(false), "netrc": ignored(false),
	"netrc-optional": ignored(false), "list-only": ignored(false),
	"progress-bar": ignored(false), "no-progress-meter": ignored(false),
	"parallel": ignored(false), "raw": ignored(false), "disable": ignored(false),
	"anyauth": ignored(false), "basic": ignored(false), "digest": ignored(false),
	"ntlm": ignored(false), "negotiate": ignored(false), "tcp-nodelay": ignored(false),
	"no-keepalive": ignored(false), "no-sessionid": ignored(false), "no-alpn": ignored(false),
	"no-npn": ignored(false), "tr-encoding": ignored(false), "xattr": ignored(false),
	"styled-output": ignored(false), "trace-time": ignored(false), "crlf": ignored(false),
	"proxy-insecure": ignored(false), "suppress-connect-headers": ignored(false),
	"ssl": ignored(false), "ssl-reqd": ignored(false), "ssl-no-revoke": ignored(false),
	"ssl-allow-beast": ignored(false), "tcp-fastopen": ignored(false),
	"post301": ignored(false), "post302": ignored(false), "post303": ignored(false),
	"sasl-ir": ignored(false), "no-clobber": ignored(false), "clobber": ignored(false),
	"disallow-username-in-url": ignored(false), "ignore-content-length": ignored(false),
	"tlsv1": ignored(false), "tlsv1.0": ignored(false), "tlsv1.1": ignored(false),
	"tlsv1.2": ignored(false), "tlsv1.3": ignored(false), "sslv2": ignored(false),
	"sslv3": ignored(false), "ipv4": ignored(false), "ipv6": ignored(false),
	"output": ignored(true), "write-out": ignored(true), "dump-header": ignored(true),
	"cookie-jar": ignored(true), "config": ignored(true), "continue-at": ignored(true),
	"range": ignored(true), "time-cond": ignored(true), "limit-rate": ignored(true),
	"local-port": ignored(true), "speed-time": ignored(true), "speed-limit": ignored(true),
	"trace": ignored(true), "trace-ascii": ignored(true), "stderr": ignored(true),
	"ciphers": ignored(true), "tls-max": ignored(true), "cert-type": ignored(true),
	"key-type": ignored(true), "pass": ignored(true), "capath": ignored(true),
	"pubkey": ignored(true), "engine": ignored(true), "krb": ignored(true),
	"proto": ignored(true), "proto-default": ignored(true), "proto-redir": ignored(true),
	"doh-url": ignored(true), "netrc-file": ignored(true), "aws-sigv4": ignored(true),
	"expect100-timeout": ignored(true), "happy-eyeballs-timeout-ms": ignored(true),
	"keepalive-time": ignored(true), "max-filesize": ignored(true),
	"retry-max-time": ignored(true), "variable": ignored(true), "next": ignored(false),
}

// setSeconds parses curl's fractional-seconds duration form (e.g. "2", "0.5").
func (s *curlSpec) setSeconds(dst *time.Duration, v, flag string) error {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || f < 0 {
		return fmt.Errorf("%s %q: want seconds (e.g. 5 or 2.5)", flag, v)
	}
	*dst = time.Duration(f * float64(time.Second))
	return nil
}
