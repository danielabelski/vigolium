package command_injection_oast

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// injectionTypeParam / injectionTypeHeader are recorded on the OAST payload
// context. They contain the word "command" so the OAST service classifies the
// resulting callback as command injection (see oast.classifyCommandInjection).
const (
	injectionTypeParam  = "os-command-injection (parameter)"
	injectionTypeHeader = "os-command-injection (header)"
)

// cmdiOASTHeaders are headers that downstream pipelines sometimes feed into a
// shell (log processors, analytics, geo lookups). Kept small to bound volume.
var cmdiOASTHeaders = []string{"User-Agent", "Referer", "X-Forwarded-For"}

// Module implements the out-of-band OS command injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds  dedup.Lazy[dedup.DiskSet]
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new out-of-band command injection module.
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
			modkit.ScanScopeRequest|modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		ds:  dedup.LazyDiskSet("command_injection_oast"),
		rhm: dedup.LazyDefaultRHM("command_injection_oast"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest injects out-of-band command payloads into command-processed
// headers. Findings arrive asynchronously via the OAST polling callback.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	// Dedup header injection by host+path.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s|hdr", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	requestHash := ctx.Request().ID()
	for _, header := range cmdiOASTHeaders {
		host := oast.GenerateURL(urlx.String(), header, injectionTypeHeader, ModuleID, requestHash)
		if host == "" {
			continue
		}
		payloads := infra.CmdiOASTHeaderPayloads(host, "http://"+host)
		// Record a representative variant (the first is always sent) so the finding
		// reconstructs the planting request with the real shell payload in the
		// header — not a bare host — even though several variants share this host.
		if len(payloads) > 0 {
			oast.RecordPayload(host, payloads[0])
		}
		for _, payload := range payloads {
			modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), header, payload)
			if err != nil {
				continue
			}
			if abort := m.fire(ctx, httpClient, modifiedRaw); abort {
				return nil, nil
			}
		}
	}

	return nil, nil
}

// ScanPerInsertionPoint injects out-of-band command payloads into a parameter.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), fmt.Sprintf("%d", ip.Type())) {
			return nil, nil
		}
	}

	requestHash := ctx.Request().ID()
	// Label the injection by its actual insertion-point kind: a header insertion
	// point (e.g. X-Forwarded-For enumerated as an insertion point) must carry the
	// "header" injection type so the finding reconstructs it as a header — not a
	// generic parameter — and applies the real payload there.
	injType := injectionTypeParam
	if ip.Type() == httpmsg.INS_HEADER {
		injType = injectionTypeHeader
	}
	host := oast.GenerateURL(urlx.String(), ip.Name(), injType, ModuleID, requestHash)
	if host == "" {
		return nil, nil
	}
	httpURL := "http://" + host

	base := ip.BaseValue()
	payloads := infra.CmdiOASTPayloads(host, httpURL)
	// Record the complete value planted at the insertion point (base + a
	// representative variant that is always sent) so the finding shows what really
	// went on the wire rather than the bare callback host.
	if len(payloads) > 0 {
		oast.RecordPayload(host, base+payloads[0])
	}
	for _, payload := range payloads {
		raw := ip.BuildRequest([]byte(base + payload))
		if abort := m.fire(ctx, httpClient, raw); abort {
			return nil, nil
		}
	}

	return nil, nil
}

// fire sends a fuzzed raw request and discards the response. It returns
// abort=true only when the host has become unresponsive, signalling the caller
// to stop probing this target.
func (m *Module) fire(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (abort bool) {
	// BuildRequest/AddOrReplaceHeader produce well-formed raw, so wrap
	// directly instead of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return errors.Is(err, hosterrors.ErrUnresponsiveHost)
	}
	resp.Close()
	return false
}
