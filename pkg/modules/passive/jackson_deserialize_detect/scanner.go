package jackson_deserialize_detect

import (
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var (
	// Type discriminator fields in JSON
	typeFieldPattern = regexp.MustCompile(`"@(?:class|type)"\s*:\s*"[a-zA-Z][\w.]*(?:\$[\w]+)*"`)
	// Java class references in JSON values
	javaClassPattern = regexp.MustCompile(`"(?:com|org|net|io|java|javax|jakarta)\.[a-z][\w.]*(?:\$[\w]+)*"`)
	// Jackson/Java deserialization error patterns
	jacksonErrorPattern = regexp.MustCompile(`(?i)(?:com\.fasterxml\.jackson|JsonMappingException|UnrecognizedPropertyException|InvalidTypeIdException|MismatchedInputException|JsonParseException.*type)`)
	deserErrorPattern   = regexp.MustCompile(`(?i)(?:java\.io\.ObjectInputStream|InvalidClassException|StreamCorruptedException|ClassNotFoundException.*deserializ|NotSerializableException)`)
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("jackson_deserialize_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	// Static assets (minified JS bundles especially) are full of reverse-DNS
	// identifiers like "io.foo"/"com.app.title" and stray Java-sounding strings.
	// A deserialization indicator inside such an asset is not a live signal, so
	// skip them outright rather than substring-matching them.
	if modkit.IsStaticAssetContentType(ct) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	var extracted []string
	detected := false

	// Type-discriminator / class-ref matching only makes sense on JSON bodies.
	// A bare Java class reference ("com.app.x") on its own is NOT evidence of
	// polymorphic deserialization — configs and payloads are full of reverse-DNS
	// identifiers — so it is only reported alongside an @class/@type discriminator,
	// which is the actual signal.
	if strings.Contains(ct, "json") {
		if matches := typeFieldPattern.FindAllString(body, 3); len(matches) > 0 {
			detected = true
			for _, match := range matches {
				extracted = append(extracted, "Type field: "+match)
			}
			if classMatches := javaClassPattern.FindAllString(body, 3); len(classMatches) > 0 {
				for _, match := range classMatches {
					extracted = append(extracted, "Java class ref: "+match)
				}
			}
		}
	}

	// Check for deserialization error patterns (any content type)
	if jacksonErrorPattern.MatchString(body) {
		detected = true
		if match := jacksonErrorPattern.FindString(body); match != "" {
			extracted = append(extracted, "Jackson error: "+match)
		}
	}
	if deserErrorPattern.MatchString(body) {
		detected = true
		if match := deserErrorPattern.FindString(body); match != "" {
			extracted = append(extracted, "Deserialization error: "+match)
		}
	}

	if !detected {
		return nil, nil
	}

	// This is a passive PRECONDITION signal ("Tentative; not confirmed
	// exploitable"), not a confirmed deserialization vuln, so it stays below
	// Medium. A leaked deserialization error is an info-disclosure lead (Info); an
	// actual @class/@type polymorphic-typing discriminator is the stronger
	// gadget-attack precondition (Low). The previous code assigned Medium in both
	// branches (a dead if), over-severing every hit.
	sev := severity.Info
	desc := "Jackson polymorphic typing or Java deserialization indicators detected in response"
	if len(extracted) > 0 && strings.Contains(extracted[0], "Type field") {
		sev = severity.Low
		desc = "JSON response contains Jackson type discriminator fields (@class/@type), suggesting polymorphic deserialization is enabled which may allow gadget-based attacks"
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Jackson/Java Deserialization Indicators",
				Description: desc,
				Severity:    sev,
				Confidence:  severity.Tentative,
				Tags:        []string{"java", "jackson", "deserialization", "rce-risk"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/502.html"},
			},
		},
	}, nil
}
