package insecure_deserialization

import (
	"fmt"
	"regexp"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// deserError defines a deserialization error pattern.
type deserError struct {
	framework string
	pattern   *regexp.Regexp
}

// errorPatterns are framework deserialization-error signatures. The two-anchor
// forms below (X ... Y) deliberately bound the gap between the anchors:
// unbounded ".*" filler lets a lazy match bridge two coincidental words tens of
// KB apart in a large single-line body (the classic "Oracle.*?Driver spanned a
// Salesforce Aura app shell" false positive), and a Java FQCN filler is further
// constrained to package-name characters ([\w.$]) so it cannot cross JSON/HTML
// structure. A genuine leak names the class in one compact phrase, so the bounds
// never clip a true positive. The general match-span guard in checkDeserError is
// the backstop for any signature that still matches too wide.
var errorPatterns = []deserError{
	{"Java", regexp.MustCompile(`(?i)(?:java\.io\.ObjectInputStream|java\.io\.InvalidClassException|java\.lang\.ClassCastException.{0,80}deserializ|ClassNotFoundException.{0,80}deserializ|InvalidObjectException|StreamCorruptedException)`)},
	{"Java", regexp.MustCompile(`(?i)(?:org\.apache\.commons\.collections\.functors|com\.sun\.org\.apache\.xalan|ysoserial|CommonsCollections)`)},
	{"PHP", regexp.MustCompile(`(?i)(?:unserialize\(\)|O:\d+:"[^"]+"|PHP Fatal error.{0,80}unserialize|__wakeup|__destruct.{0,40}called)`)},
	{"Python", regexp.MustCompile(`(?i)(?:pickle\.loads|cPickle\.loads|_pickle\.UnpicklingError|yaml\.load|yaml\.unsafe_load)`)},
	{"Ruby", regexp.MustCompile(`(?i)(?:Marshal\.load|YAML\.load|Psych::DisallowedClass|ERB\.{0,20}new.{0,80}result|Gem::Installer)`)},
	{".NET", regexp.MustCompile(`(?i)(?:System\.Runtime\.Serialization|BinaryFormatter|SoapFormatter|ObjectStateFormatter|LosFormatter|NetDataContractSerializer|TypeNameHandling)`)},
	{"Java", regexp.MustCompile(`(?i)(?:org\.apache\.commons\.beanutils|com\.sun\.rowset\.JdbcRowSetImpl|org\.hibernate\.[\w.$]{0,80}Exception|org\.springframework\.[\w.$]{0,80}SerializationException)`)},
}

// deserPayload defines a deserialization probe.
type deserPayload struct {
	payload string
	desc    string
}

var payloads = []deserPayload{
	{
		// Java serialized object magic bytes (base64 of 0xACED0005)
		payload: "\xac\xed\x00\x05sr\x00\x01A",
		desc:    "Java serialization magic bytes",
	},
	{
		payload: `O:8:"stdClass":0:{}`,
		desc:    "PHP serialize format",
	},
	{
		payload: `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"}`,
		desc:    ".NET TypeNameHandling probe",
	},
	{
		payload: "!!python/object/apply:os.system ['id']",
		desc:    "Python YAML deserialization",
	},
	{
		payload: "\x04\x08o:\x30ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy",
		desc:    "Ruby Marshal.load probe",
	},
	{
		payload: `{"$type":"System.Windows.Forms.AxHost+State, System.Windows.Forms"}`,
		desc:    ".NET AxHost State deserialization",
	},
}

// Module implements the Insecure Deserialization active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Insecure Deserialization module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeInsertionPoint,
			modkit.BodyParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("insecure_deserialization"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for deserialization vulnerabilities.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Get original response body to filter false positives
	var origBody string
	if ctx.Response() != nil {
		origBody = ctx.Response().BodyToString()
	}

	var results []*output.ResultEvent

	for _, p := range payloads {
		fuzzedRaw := ip.BuildRequest([]byte(p.payload))

		// BuildRequest produces well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// A WAF/CDN challenge, auth gate, or rate-limit page is not the app
		// surfacing a deserialization error — skip it so its body can't trip the
		// signature (the SSO/Cloudflare-challenge false-positive class).
		if infra.IsBlockedResponse(resp) {
			resp.Close()
			continue
		}

		// A 404 / redirect means the route never resolved, so no deserialization
		// ran: a framework class-name or error substring in such a body is page
		// noise (a JS bundle, a SPA shell), not a leaked deserialization error.
		// Mirrors the sqli/nosqli error-based modules — only a genuine application
		// error surface can carry the leak.
		if !infra.IsErrorSurfaceStatus(resp) {
			resp.Close()
			continue
		}

		body := resp.Body().String()
		if framework, matched := checkDeserError(body, origBody, p.payload); matched {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.FullResponseString(),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{p.payload, p.desc},
				Info: output.Info{
					Description: fmt.Sprintf("Framework: %s — %s", framework, p.desc),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// checkDeserError reports whether the response surfaced a framework
// deserialization error signature that is ABSENT from the baseline.
//
// The injected payload is stripped (modkit.StripReflected) before matching:
// several serialized wire formats are themselves matched by the framework error
// patterns — most notably PHP's O:N:"class":... form, which satisfies the
// `O:\d+:"[^"]+"` alternative — so an endpoint that merely REFLECTS the rejected
// payload back in an error or echo (e.g. `invalid input: O:8:"stdClass":0:{}`)
// would otherwise self-trigger a High/Firm finding without ever deserializing
// anything. Removing the reflected payload first leaves only server-emitted text,
// so a genuine unserialize() / __wakeup() / ObjectInputStream signature still
// matches while a bare echo of our own probe does not. (An error that quotes the
// payload amid a real signature — `unserialize(): Error ... O:8:"stdClass":0:{}` —
// still matches on the surviving `unserialize()` keyword.)
func checkDeserError(body, origBody, payload string) (string, bool) {
	body = modkit.StripReflected(body, payload)
	for _, ep := range errorPatterns {
		// Accept only a plausibly compact signature span (the shared error-based
		// guard), so a two-anchor pattern whose filler bridged unrelated content on
		// a large body is not read as a leak.
		if !modkit.MatchWithinSpan(ep.pattern, body, modkit.MaxErrorSignatureSpan) {
			continue
		}
		if origBody != "" && ep.pattern.MatchString(origBody) {
			continue
		}
		return ep.framework, true
	}
	return "", false
}
