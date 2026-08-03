package curl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requestTarget returns the host and request-line target of a parsed command,
// which is what the "did we fuzz the right thing" assertions care about.
func requestTarget(t *testing.T, cmd string) (host, target, raw string) {
	t.Helper()
	rr, err := ParseSingleCommand(cmd)
	require.NoError(t, err)
	raw = string(rr.Request().Raw())
	line, _, _ := strings.Cut(raw, "\r\n")
	fields := strings.Fields(line)
	require.Len(t, fields, 3, "request line %q", line)
	return rr.Request().Service().Host(), fields[1], raw
}

// Previously any flag the parser didn't know was skipped while its value was
// left to be picked up as the URL — so `-e https://referer/` silently
// retargeted the request at the referer's host.
func TestArgTakingFlagsDoNotBecomeTheURL(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"user-agent", `curl -A 'Mozilla/5.0' https://target.test/api?id=1`},
		{"referer", `curl -e https://referer.test/ https://target.test/api`},
		{"proxy", `curl -x http://127.0.0.1:8080 https://target.test/api`},
		{"connect-timeout", `curl --connect-timeout 5 https://target.test/api`},
		{"max-time", `curl -m 30 https://target.test/api`},
		{"cookie-jar", `curl -c /tmp/jar.txt https://target.test/api`},
		{"write-out", `curl -w '%{http_code}' https://target.test/api`},
		{"resolve", `curl --resolve target.test:443:127.0.0.1 https://target.test/api`},
		{"limit-rate", `curl --limit-rate 100k https://target.test/api`},
		{"cert", `curl -E client.pem https://target.test/api`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, _, _ := requestTarget(t, tc.cmd)
			assert.Equal(t, "target.test", host)
		})
	}
}

func TestUnknownFlagIsRejected(t *testing.T) {
	_, err := ParseSingleCommand(`curl --totally-not-a-curl-flag value https://target.test/`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized curl flag")
	assert.Contains(t, err.Error(), "--totally-not-a-curl-flag")
}

func TestMultipleURLsRejected(t *testing.T) {
	_, err := ParseSingleCommand(`curl https://a.test/ https://b.test/`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple URLs")
}

func TestUserAgentAndRefererBecomeHeaders(t *testing.T) {
	_, _, raw := requestTarget(t, `curl -A 'vigolium/1.0' -e 'https://referer.test/' https://target.test/`)
	assert.Contains(t, raw, "User-Agent: vigolium/1.0")
	assert.Contains(t, raw, "Referer: https://referer.test/")
}

func TestExplicitHeaderBeatsSynthesized(t *testing.T) {
	_, _, raw := requestTarget(t, `curl -A 'from-flag' -H 'User-Agent: from-header' https://target.test/`)
	assert.Contains(t, raw, "User-Agent: from-header")
	assert.NotContains(t, raw, "from-flag")
}

func TestHeadFlagUsesHEAD(t *testing.T) {
	for _, cmd := range []string{`curl -I https://target.test/`, `curl --head https://target.test/`} {
		rr, err := ParseSingleCommand(cmd)
		require.NoError(t, err)
		assert.Equal(t, "HEAD", rr.Request().Method(), cmd)
	}
}

// -G sends the data as query parameters on a GET, not as a POST body.
func TestGetFlagMovesDataToQuery(t *testing.T) {
	rr, err := ParseSingleCommand(`curl -G -d 'a=b' -d 'c=d' https://target.test/api`)
	require.NoError(t, err)
	assert.Equal(t, "GET", rr.Request().Method())

	raw := string(rr.Request().Raw())
	line, _, _ := strings.Cut(raw, "\r\n")
	assert.Contains(t, line, "a=b")
	assert.Contains(t, line, "c=d")
	assert.NotContains(t, raw, "\r\n\r\na=b")
}

func TestGetFlagMergesWithExistingQuery(t *testing.T) {
	_, target, _ := requestTarget(t, `curl -G -d 'b=2' 'https://target.test/api?a=1'`)
	assert.Contains(t, target, "a=1")
	assert.Contains(t, target, "b=2")
}

func TestDataURLEncodeForms(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "payload.txt")
	require.NoError(t, os.WriteFile(file, []byte("hello world&x"), 0o600))

	cases := []struct {
		name string
		arg  string
		want string
	}{
		{"content", `q a`, "q+a"},
		{"equals-content", `=a b`, "a+b"},
		{"name-content", `q=a b`, "q=a+b"},
		{"name-file", `q@` + file, "q=hello+world%26x"},
		{"file-only", `@` + file, "hello+world%26x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := ParseSingleCommand(`curl --data-urlencode '` + tc.arg + `' https://target.test/api`)
			require.NoError(t, err)
			assert.Contains(t, string(rr.Request().Raw()), tc.want)
		})
	}
}

func TestDataFromFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "body.json")
	require.NoError(t, os.WriteFile(file, []byte("{\"a\":1}\n"), 0o600))

	// --data strips newlines; --data-binary keeps them.
	_, _, ascii := requestTarget(t, `curl -d @`+file+` https://target.test/api`)
	assert.Contains(t, ascii, `{"a":1}`)
	assert.Contains(t, ascii, "Content-Length: 7")

	_, _, binary := requestTarget(t, `curl --data-binary @`+file+` https://target.test/api`)
	assert.Contains(t, binary, "Content-Length: 8")

	// --data-raw treats '@' as a literal.
	_, _, rawData := requestTarget(t, `curl --data-raw @`+file+` https://target.test/api`)
	assert.Contains(t, rawData, "@"+file)
}

func TestMissingDataFileIsFatal(t *testing.T) {
	_, err := ParseSingleCommand(`curl -d @/definitely/not/here.json https://target.test/api`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read data file")
}

// -F must produce a real multipart body with a boundary that matches the
// Content-Type; the previous implementation emitted a urlencoded body under a
// boundary-less multipart header, which no server can parse.
func TestFormBuildsRealMultipart(t *testing.T) {
	_, _, raw := requestTarget(t, `curl -F 'field=value' -F 'file=@photo.jpg' https://target.test/upload`)

	_, ctLine, ok := strings.Cut(raw, "Content-Type: ")
	require.True(t, ok)
	ctLine, _, _ = strings.Cut(ctLine, "\r\n")
	require.True(t, strings.HasPrefix(ctLine, "multipart/form-data; boundary="))

	boundary := strings.TrimPrefix(ctLine, "multipart/form-data; boundary=")
	require.NotEmpty(t, boundary)

	assert.Contains(t, raw, "--"+boundary+"\r\n")
	assert.Contains(t, raw, "--"+boundary+"--\r\n")
	assert.Contains(t, raw, `Content-Disposition: form-data; name="field"`)
	assert.Contains(t, raw, `Content-Disposition: form-data; name="file"; filename="photo.jpg"`)
	assert.Contains(t, raw, "value")
}

func TestFormBoundaryIsDeterministic(t *testing.T) {
	cmd := `curl -F 'a=1' -F 'b=2' https://target.test/upload`
	_, _, first := requestTarget(t, cmd)
	_, _, second := requestTarget(t, cmd)
	assert.Equal(t, first, second)
}

func TestFormStringIsLiteral(t *testing.T) {
	_, _, raw := requestTarget(t, `curl --form-string 'note=@notafile' https://target.test/upload`)
	assert.Contains(t, raw, "@notafile")
}

// curl's default for -d is form-urlencoded; a JSON body still gets a JSON
// content type because pasted commands routinely omit the header.
func TestDataContentTypeDefaults(t *testing.T) {
	_, _, form := requestTarget(t, `curl -d 'a=b&c=d' https://target.test/api`)
	assert.Contains(t, form, "Content-Type: application/x-www-form-urlencoded")

	_, _, js := requestTarget(t, `curl -d '{"a":1}' https://target.test/api`)
	assert.Contains(t, js, "Content-Type: application/json")
}

func TestJSONShorthand(t *testing.T) {
	_, _, raw := requestTarget(t, `curl --json '{"a":1}' https://target.test/api`)
	assert.Contains(t, raw, "Content-Type: application/json")
	assert.Contains(t, raw, "Accept: application/json")
	assert.Contains(t, raw, `{"a":1}`)
}

func TestUploadFileUsesPUT(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "up.txt")
	require.NoError(t, os.WriteFile(file, []byte("contents"), 0o600))

	rr, err := ParseSingleCommand(`curl -T ` + file + ` https://target.test/dest`)
	require.NoError(t, err)
	assert.Equal(t, "PUT", rr.Request().Method())
	assert.Contains(t, string(rr.Request().Raw()), "contents")
}

func TestShortFlagClusteringAndAttachedValues(t *testing.T) {
	// -sSL clusters three no-arg flags; -XPOST attaches the value.
	rr, err := ParseSingleCommand(`curl -sSL -XPOST -H'X-A: 1' https://target.test/api`)
	require.NoError(t, err)
	assert.Equal(t, "POST", rr.Request().Method())
	assert.Contains(t, string(rr.Request().Raw()), "X-A: 1")

	// An arg-taking flag at the end of a cluster takes the next token.
	rr2, err := ParseSingleCommand(`curl -skX PUT https://target.test/api`)
	require.NoError(t, err)
	assert.Equal(t, "PUT", rr2.Request().Method())
}

func TestLongFlagEqualsForm(t *testing.T) {
	rr, err := ParseSingleCommand(`curl --request=DELETE --header='X-B: 2' https://target.test/api`)
	require.NoError(t, err)
	assert.Equal(t, "DELETE", rr.Request().Method())
	assert.Contains(t, string(rr.Request().Raw()), "X-B: 2")
}

func TestEndOfFlagsMarker(t *testing.T) {
	host, _, _ := requestTarget(t, `curl -s -- https://target.test/api`)
	assert.Equal(t, "target.test", host)
}

func TestNegatedBooleanFlagIgnored(t *testing.T) {
	host, _, _ := requestTarget(t, `curl --no-compressed https://target.test/api`)
	assert.Equal(t, "target.test", host)
}

func TestTransportHintsCaptured(t *testing.T) {
	_, hints, err := ParseSingleCommandWithHints(
		`curl -x http://127.0.0.1:8080 -k -L --max-redirs 3 --connect-timeout 2.5 -m 30 ` +
			`--resolve target.test:443:10.0.0.1 --http1.1 --cert c.pem --key k.pem --cacert ca.pem ` +
			`--compressed --path-as-is --retry 2 https://target.test/api`)
	require.NoError(t, err)

	assert.Equal(t, "http://127.0.0.1:8080", hints.Proxy)
	assert.True(t, hints.Insecure)
	assert.True(t, hints.Location)
	assert.Equal(t, 3, hints.MaxRedirs)
	assert.Equal(t, 2500*time.Millisecond, hints.ConnectTimeout)
	assert.Equal(t, 30*time.Second, hints.MaxTime)
	assert.Equal(t, []string{"target.test:443:10.0.0.1"}, hints.Resolve)
	assert.Equal(t, "1.1", hints.HTTPVersion)
	assert.Equal(t, "c.pem", hints.ClientCert)
	assert.Equal(t, "k.pem", hints.ClientKey)
	assert.Equal(t, "ca.pem", hints.CACert)
	assert.True(t, hints.Compressed)
	assert.True(t, hints.PathAsIs)
	assert.Equal(t, 2, hints.Retry)
	assert.False(t, hints.IsZero())
}

func TestTransportHintsZeroForPlainCommand(t *testing.T) {
	_, hints, err := ParseSingleCommandWithHints(`curl https://target.test/api`)
	require.NoError(t, err)
	assert.True(t, hints.IsZero())
}

func TestCurlPrefixVariants(t *testing.T) {
	for _, cmd := range []string{
		`curl https://target.test/api`,
		`/usr/bin/curl https://target.test/api`,
		`$ curl https://target.test/api`,
	} {
		host, _, _ := requestTarget(t, cmd)
		assert.Equal(t, "target.test", host, cmd)
	}
}

func TestBearerAndBasicAuth(t *testing.T) {
	_, _, basic := requestTarget(t, `curl -u admin:s3cret https://target.test/api`)
	assert.Contains(t, basic, "Authorization: Basic YWRtaW46czNjcmV0")

	_, _, bearer := requestTarget(t, `curl --oauth2-bearer tok123 https://target.test/api`)
	assert.Contains(t, bearer, "Authorization: Bearer tok123")
}

func TestMultipleCookieFlagsMerge(t *testing.T) {
	_, _, raw := requestTarget(t, `curl -b 'a=1' -b 'b=2' https://target.test/api`)
	assert.Contains(t, raw, "Cookie: a=1; b=2")
}
