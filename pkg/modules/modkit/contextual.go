package modkit

import (
	"context"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// RequestScopeContextStubs supplies the two no-op ContextualActiveModule methods
// (ScanPerInsertionPointContext / ScanPerHostContext) that a ScanScopeRequest-only
// module has no use for. Embed it and implement only ScanPerRequestContext to make a
// request-scope module deadline-aware without hand-writing the boilerplate stubs.
//
// Embedding it alone does NOT satisfy modules.ContextualActiveModule — the module
// must still supply ScanPerRequestContext itself — so a legacy request module can
// never accidentally be routed onto the executor's contextual path.
type RequestScopeContextStubs struct{}

// ScanPerInsertionPointContext is a no-op: a request-scope module does no per-point work.
func (RequestScopeContextStubs) ScanPerInsertionPointContext(context.Context, *httpmsg.HttpRequestResponse, httpmsg.InsertionPoint, *http.Requester, *ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

// ScanPerHostContext is a no-op: a request-scope module does no per-host work.
func (RequestScopeContextStubs) ScanPerHostContext(context.Context, *httpmsg.HttpRequestResponse, *http.Requester, *ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
