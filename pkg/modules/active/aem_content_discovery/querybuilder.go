package aem_content_discovery

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const qbBase = "/bin/querybuilder.json"

// qbForm is a locked QueryBuilder request form: the index into
// aem.AllBypasses(qbBase?<query>) whose variant reached the servlet. The index is
// stable across queries (the bypass list ordering is structural), so one probe
// locks the working form for every predicate query that follows.
type qbForm struct {
	idx int
}

func (f qbForm) query(rawQuery string) string {
	return aem.BypassAtIndex(qbBase+"?"+rawQuery, f.idx)
}

func (f qbForm) isBypass() bool { return f.idx > 0 }

var qbTotalRe = regexp.MustCompile(`"total"\s*:\s*(\d+)`)

// qbTotal returns the QueryBuilder result total, or -1 when the body is not a
// successful QueryBuilder response.
func qbTotal(res aem.ProbeResult) int {
	if !res.OK || res.Status != 200 || !strings.Contains(res.Body, `"success":true`) {
		return -1
	}
	mm := qbTotalRe.FindStringSubmatch(res.Body)
	if mm == nil {
		return -1
	}
	n, _ := strconv.Atoi(mm[1]) // qbTotalRe guarantees mm[1] is all digits
	return n
}

// hasPermQuery is the QueryBuilder query that returns nodes on which the anonymous
// session holds the given JCR privilege (CVE-2025-54246 solution #1).
func hasPermQuery(perm string) string {
	return "property=jcr:uuid&property.operation=exists&p.hits=selective&p.properties=jcr:path&p.limit=5&hasPermission=" + perm
}

func (m *Module) runQueryBuilder(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	baseURL string,
) []*output.ResultEvent {
	form, ok := m.findQueryBuilder(ctx, httpClient)
	if !ok {
		return nil
	}

	var results []*output.ResultEvent
	if res := m.probeWritableNodes(ctx, httpClient, form, baseURL); res != nil {
		results = append(results, res)
	}
	if res := m.probePackages(ctx, httpClient, form, baseURL); res != nil {
		results = append(results, res)
	}
	return results
}

// findQueryBuilder locks the first QueryBuilder form (clean or bypassed) that
// returns a successful result and reproduces.
func (m *Module) findQueryBuilder(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) (qbForm, bool) {
	const probeQuery = "p.limit=1&p.hits=selective&p.properties=jcr:path&type=nt:base"
	cands := aem.AllBypasses(qbBase + "?" + probeQuery)
	for i, path := range cands {
		res := aem.Get(ctx, httpClient, path, nil)
		if qbTotal(res) < 0 || modkit.ResemblesObservedPage(ctx, res.Body) {
			continue
		}
		if !aem.ReproduceMarker(ctx, httpClient, path, reproduceRounds, func(r aem.ProbeResult) bool {
			return qbTotal(r) >= 0
		}) {
			continue
		}
		return qbForm{idx: i}, true
	}
	return qbForm{}, false
}

// writePermissions are the JCR privileges whose presence on a node reachable by the
// anonymous session means an attacker can create/modify content (CVE-2025-54246
// solution #1: locate misconfigured writable nodes).
var writePermissions = []string{"jcr:write", "jcr:addChildNodes", "jcr:modifyProperties"}

func (m *Module) probeWritableNodes(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	form qbForm,
	baseURL string,
) *output.ResultEvent {
	for _, perm := range writePermissions {
		path := form.query(hasPermQuery(perm))
		res := aem.Get(ctx, httpClient, path, nil)
		if qbTotal(res) <= 0 || modkit.ResemblesObservedPage(ctx, res.Body) {
			continue
		}
		// Negative control: a bogus privilege must NOT return hits. If it does, the
		// endpoint is a catch-all echoing results for any predicate — not a real
		// writable-node disclosure.
		neg := aem.Get(ctx, httpClient, form.query(hasPermQuery("jcr:"+modkit.FreshCanary())), nil)
		if qbTotal(neg) > 0 {
			continue
		}
		if !aem.ReproduceMarker(ctx, httpClient, path, reproduceRounds, func(r aem.ProbeResult) bool {
			return qbTotal(r) > 0
		}) {
			continue
		}
		return m.buildWritable(form, perm, extractPaths(res.Body), path, baseURL)
	}
	return nil
}

func (m *Module) probePackages(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	form qbForm,
	baseURL string,
) *output.ResultEvent {
	q := "type=nt:file&nodename=*.zip&p.hits=selective&p.properties=jcr:path&p.limit=5"
	path := form.query(q)
	res := aem.Get(ctx, httpClient, path, nil)
	if qbTotal(res) <= 0 || !strings.Contains(res.Body, ".zip") || modkit.ResemblesObservedPage(ctx, res.Body) {
		return nil
	}
	// Negative control: an impossible nodename must return zero.
	neg := aem.Get(ctx, httpClient, form.query("type=nt:file&nodename=*."+modkit.FreshCanary()+".zzz&p.hits=selective&p.properties=jcr:path&p.limit=5"), nil)
	if qbTotal(neg) > 0 {
		return nil
	}
	if !aem.ReproduceMarker(ctx, httpClient, path, reproduceRounds, func(r aem.ProbeResult) bool {
		return qbTotal(r) > 0 && strings.Contains(r.Body, ".zip")
	}) {
		return nil
	}
	return m.buildPackages(form, extractPaths(res.Body), path, baseURL)
}

var jcrPathRe = regexp.MustCompile(`"jcr:path"\s*:\s*"([^"]+)"`)

// extractPaths pulls the jcr:path values out of a selective QueryBuilder result.
func extractPaths(body string) []string {
	mm := jcrPathRe.FindAllStringSubmatch(body, maxEvidenceNodes)
	out := make([]string, 0, len(mm))
	for _, m := range mm {
		out = append(out, m[1])
	}
	return out
}

func (m *Module) buildWritable(form qbForm, perm string, paths []string, reqPath, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + reqPath
	evidence := []string{
		"privilege: " + perm,
		"discovered via QueryBuilder hasPermission predicate" + qbBypassNote(form),
	}
	if len(paths) > 0 {
		evidence = append(evidence, "writable nodes: "+strings.Join(paths, ", "))
	}

	res := &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             aem.HostFromBase(baseURL),
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name: "AEM Anonymous Writable JCR Node",
			Description: fmt.Sprintf(
				"The QueryBuilder hasPermission=%s predicate returned repository nodes writable by the unauthenticated session (a bogus-privilege negative control returned none, ruling out a catch-all). Anonymous write access lets an attacker create nodes that AEM renders as scripts/components — the classic route to persistent XSS and stored-script execution (e.g. the /content/usergenerated/etc/commerce/smartlists smartlists bug).",
				perm,
			),
			Severity:   severity.High,
			Confidence: severity.Firm,
			Tags:       append([]string{"aem", "adobe", "misconfiguration", "acl", "jcr", "content-discovery"}, aem.ACLBypassTag(form.isBypass())...),
			Reference:  append([]string{"https://nvd.nist.gov/vuln/detail/CVE-2025-54246"}, refs...),
		},
	}
	if form.isBypass() {
		modkit.AnnotatePathBypassFinding(res, reqPath)
	}
	return res
}

func (m *Module) buildPackages(form qbForm, paths []string, reqPath, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + reqPath
	evidence := []string{"discovered via QueryBuilder type=nt:file nodename=*.zip" + qbBypassNote(form)}
	if len(paths) > 0 {
		evidence = append(evidence, "archives: "+strings.Join(paths, ", "))
	}

	res := &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             aem.HostFromBase(baseURL),
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name: "AEM Deployment Package / Archive Disclosure",
			Description: "QueryBuilder enumerated .zip archives in the repository (typically /etc/packages build packages, or config backups). AEM deployment packages routinely contain application source and plaintext infrastructure credentials, and are downloadable once located.",
			Severity:   severity.High,
			Confidence: severity.Firm,
			Tags:       append([]string{"aem", "adobe", "info-disclosure", "content-discovery", "jcr"}, aem.ACLBypassTag(form.isBypass())...),
			Reference:  refs,
		},
	}
	if form.isBypass() {
		modkit.AnnotatePathBypassFinding(res, reqPath)
	}
	return res
}

func qbBypassNote(form qbForm) string {
	if form.isBypass() {
		return " (through a dispatcher bypass)"
	}
	return ""
}
