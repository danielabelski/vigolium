package aem_content_discovery

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	// Traversal bounds. The module is a detector, not an exfiltration tool: it walks
	// just deep enough to prove the repository is enumerable and to surface
	// high-value leaks, then stops.
	maxNodeReads       = 24 // total DefaultGetServlet reads across the walk
	maxDepth           = 2  // seed(0) -> child(1) -> grandchild(2)
	maxChildrenPerNode = 12 // children enqueued from one node's .1.json
	maxEvidenceNodes   = 12 // node paths listed in a finding
	minNodesForFinding = 3  // reached-node floor before reporting a walk
	readProbeBudget    = 40 // total probes spent locating a working read primitive
)

// seeds are the JCR roots the walk starts from. Reading "/" enumerates the
// top-level nodes, and the explicit high-value roots are seeded directly so the
// walk still reaches them if "/" itself is denied.
var seeds = []string{"/", "/content", "/apps", "/etc", "/home", "/var", "/conf"}

var refs = []string{
	"https://slcyber.io/research-center/finding-critical-bugs-in-adobe-experience-manager/",
	"https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps",
}

// readForm is a locked DefaultGetServlet read primitive: the index into
// aem.AllBypasses(<path>.1.json) whose variant returned real JCR JSON. Because the
// bypass list is deterministic and structural, the same index re-applies to any
// node path, so one probe locks the working form for the whole walk.
type readForm struct {
	idx    int
	sample string // an example rendered request path (for evidence)
}

// render turns a JCR node path into the request target for the locked read form.
func (f readForm) render(nodePath string) string {
	return aem.BypassAtIndex(nodePath+".1.json", f.idx)
}

// isBypass reports whether the locked form is a dispatcher bypass (index 0 is the
// clean path in aem.AllBypasses).
func (f readForm) isBypass() bool { return f.idx > 0 }

func (m *Module) runTreeWalk(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	baseURL string,
) []*output.ResultEvent {
	form, ok := m.findReadPrimitive(ctx, httpClient)
	if !ok {
		return nil
	}

	w := m.walk(ctx, httpClient, form)
	if len(w.reached) < minNodesForFinding || w.maxDepth < 1 {
		// A single readable root is just a DefaultGetServlet dump (already reported by
		// aem_sensitive_servlet). Only report once recursion through discovered child
		// nodes actually enumerated the tree.
		return nil
	}

	var results []*output.ResultEvent

	// Configuration secret / credential material found in a walked node — Critical.
	for _, hit := range w.secretHits {
		if !aem.ReproduceMarker(ctx, httpClient, hit.reqPath, reproduceRounds, func(r aem.ProbeResult) bool {
			_, mok := matchSecret(r.Body)
			return mok
		}) {
			continue
		}
		results = append(results, m.buildSecret(form, w, hit, baseURL))
		break // one grouped credential finding is enough
	}

	// User-account enumeration — High.
	if w.userEnumReq != "" && aem.ReproduceMarker(ctx, httpClient, w.userEnumReq, reproduceRounds, func(r aem.ProbeResult) bool {
		_, uok := matchUserEnum(w.userEnumPath, r.Body)
		return uok
	}) {
		results = append(results, m.buildUserEnum(form, w, baseURL))
	}

	// The tree enumeration itself — Medium (repository structure disclosure). Emit
	// only if the read primitive re-confirms independently at report time, so a
	// transiently-readable endpoint cannot produce a structure-disclosure finding.
	if aem.ReproduceMarker(ctx, httpClient, form.sample, reproduceRounds, isJCRJSON) {
		results = append(results, m.buildTreeWalk(form, w, baseURL))
	}
	return results
}

// findReadPrimitive locks the first DefaultGetServlet .1.json form (clean or
// bypassed) that returns real JCR JSON for a canonical anchor node and reproduces.
// A total-request budget bounds the worst case: a locked-down but confirmed-AEM
// host (every variant misses) stops at readProbeBudget probes instead of sweeping
// every anchor × variant.
func (m *Module) findReadPrimitive(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) (readForm, bool) {
	budget := readProbeBudget
	for _, anchor := range []string{"/libs", "/", "/content", "/etc", "/apps"} {
		for i, path := range aem.AllBypasses(anchor + ".1.json") {
			if budget <= 0 {
				return readForm{}, false
			}
			res := aem.Get(ctx, httpClient, path, nil)
			budget--
			if !isJCRJSON(res) || modkit.ResemblesObservedPage(ctx, res.Body) {
				continue
			}
			if !aem.ReproduceMarker(ctx, httpClient, path, reproduceRounds, func(r aem.ProbeResult) bool {
				return isJCRJSON(r)
			}) {
				continue
			}
			return readForm{idx: i, sample: path}, true
		}
	}
	return readForm{}, false
}

type secretHit struct {
	path    string // JCR node path
	reqPath string // rendered request path used to read it
	marker  string
}

type walkState struct {
	reached     []string
	maxDepth    int
	secretHits  []secretHit
	userEnumPath string
	userEnumReq  string
	userEnumID   string
}

type walkItem struct {
	path  string
	depth int
}

// walk performs a bounded breadth-first traversal of the JCR tree using the locked
// read form, harvesting secret and user-enumeration markers as it goes.
func (m *Module) walk(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, form readForm) walkState {
	var st walkState
	visited := map[string]bool{}
	queue := make([]walkItem, 0, len(seeds))
	for _, s := range seeds {
		queue = append(queue, walkItem{path: s, depth: 0})
	}

	reads := 0
	for len(queue) > 0 && reads < maxNodeReads {
		item := queue[0]
		queue = queue[1:]
		if visited[item.path] {
			continue
		}
		visited[item.path] = true

		reqPath := form.render(item.path)
		if reqPath == "" {
			continue
		}
		res := aem.Get(ctx, httpClient, reqPath, nil)
		reads++
		if !isJCRJSON(res) || modkit.ResemblesObservedPage(ctx, res.Body) {
			continue
		}

		st.reached = append(st.reached, item.path)
		if item.depth > st.maxDepth {
			st.maxDepth = item.depth
		}

		if marker, ok := matchSecret(res.Body); ok {
			st.secretHits = append(st.secretHits, secretHit{path: item.path, reqPath: reqPath, marker: marker})
		}
		if id, ok := matchUserEnum(item.path, res.Body); ok && st.userEnumReq == "" {
			st.userEnumPath = item.path
			st.userEnumReq = reqPath
			st.userEnumID = id
		}

		if item.depth < maxDepth {
			for _, name := range childNames(res.Body) {
				cp := childPath(item.path, name)
				if !visited[cp] {
					queue = append(queue, walkItem{path: cp, depth: item.depth + 1})
				}
			}
		}
	}
	return st
}

// isJCRJSON reports whether a probe response is a genuine JCR node rendering: a 200
// with the jcr:primaryType anchor and a JSON shape.
//
// Content-type discipline defeats the catch-all/echo body-truncation FP: a
// DefaultGetServlet .json rendering is application/json, never an HTML *document*.
// A reflecting/catch-all host (a wildcard dispatcher rewrite, an SPA fallback)
// answers arbitrary paths with a themed text/html shell, and a gzip + bogus
// Content-Length:0 quirk can leave only a partial body tail that happens to carry
// a "jcr:primaryType" substring and begin with "{". The body-starts-with-"{"
// fallback below would then re-admit that HTML page, so an explicit HTML reject
// runs first — a real JCR node simply never comes back as text/html.
func isJCRJSON(res aem.ProbeResult) bool {
	if !res.OK || res.Status != 200 {
		return false
	}
	if modkit.ClassifyContentType(res.ContentType) == modkit.ContentClassHTML {
		return false
	}
	if !strings.Contains(res.Body, "jcr:primaryType") {
		return false
	}
	return aem.IsJSONContentType(res.ContentType) || strings.HasPrefix(strings.TrimSpace(res.Body), "{")
}

// childNames returns the child-node names of a DefaultGetServlet .1.json body: the
// object-valued keys (scalar properties are strings/numbers, multi-valued
// properties are arrays; only child nodes render as nested objects).
func childNames(body string) []string {
	var raw map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &raw) != nil {
		return nil
	}
	names := make([]string, 0, len(raw))
	for k, v := range raw {
		if k == "" || len(k) > 80 || strings.Contains(k, "/") {
			continue
		}
		t := strings.TrimSpace(string(v))
		if strings.HasPrefix(t, "{") {
			names = append(names, k)
			if len(names) >= maxChildrenPerNode {
				break
			}
		}
	}
	return names
}

func childPath(parent, name string) string {
	if parent == "/" {
		return "/" + name
	}
	return parent + "/" + name
}

// --- secret / user-enum harvesting ---------------------------------------------

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

// secretPatterns capture the value so a placeholder can be filtered out. Keys are
// bounded by quotes so "passwordField" cannot match the "password" rule.
var secretPatterns = []secretPattern{
	{"rep:password hash", regexp.MustCompile(`"rep:password"\s*:\s*"([^"]{6,})"`)},
	{"password property", regexp.MustCompile(`"(?i:password|pwd)"\s*:\s*"([^"]{3,})"`)},
	{"access/secret key", regexp.MustCompile(`"(?i:accessKey|access_key|secretKey|secret_key)"\s*:\s*"([^"]{6,})"`)},
	{"secret/token/private key", regexp.MustCompile(`"(?i:sharedSecret|privateKey|apiKey|api_key)"\s*:\s*"([^"]{8,})"`)},
	{"jdbc connection", regexp.MustCompile(`"(?i:jdbcconnectionuri|connectionString)"\s*:\s*"([^"]{8,})"`)},
}

var placeholderValue = regexp.MustCompile(`^(?i:changeme|change-me|password|passwd|x{2,}|\*{2,}|null|none|n/?a|example|placeholder|your-?password|admin|user|test)$`)

// matchSecret reports the first credential/secret marker whose value is not an
// obvious placeholder.
func matchSecret(body string) (string, bool) {
	for _, p := range secretPatterns {
		mm := p.re.FindStringSubmatch(body)
		if mm == nil {
			continue
		}
		if placeholderValue.MatchString(strings.TrimSpace(mm[1])) {
			continue
		}
		return p.name, true
	}
	return "", false
}

var authorizableIDRe = regexp.MustCompile(`"rep:authorizableId"\s*:\s*"([^"]+)"`)

// matchUserEnum reports whether a node body enumerates AEM user accounts.
func matchUserEnum(path, body string) (string, bool) {
	if strings.Contains(body, `"rep:authorizableId"`) && strings.Contains(body, "rep:User") {
		if mm := authorizableIDRe.FindStringSubmatch(body); mm != nil {
			return mm[1], true
		}
		return "", true
	}
	if strings.HasPrefix(path, "/home/") && strings.Contains(body, "rep:User") {
		return "", true
	}
	return "", false
}

// --- finding builders ----------------------------------------------------------

func (m *Module) buildTreeWalk(form readForm, w walkState, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + form.sample
	evidence := []string{
		"read primitive: DefaultGetServlet " + primitiveLabel(form),
		fmt.Sprintf("enumerated %d nodes to depth %d via .1.json child recursion", len(w.reached), w.maxDepth),
	}
	evidence = append(evidence, "nodes: "+strings.Join(capNodes(w.reached), ", "))

	res := &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             aem.HostFromBase(baseURL),
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name: "AEM Repository Tree Enumeration",
			Description: fmt.Sprintf(
				"AEM's DefaultGetServlet renders the JCR repository as JSON. Starting from the repository roots, %d nodes were enumerated to depth %d by following child-node names returned by the .1.json selector%s. The exposed tree structure leaks internal paths, component types, and authoring metadata.",
				len(w.reached), w.maxDepth, bypassClause(form),
			),
			Severity:   severity.Medium,
			Confidence: severity.Firm,
			Tags:       append([]string{"aem", "adobe", "info-disclosure", "content-discovery", "jcr"}, aem.ACLBypassTag(form.isBypass())...),
			Reference:  refs,
		},
	}
	if form.isBypass() {
		modkit.AnnotatePathBypassFinding(res, form.sample)
	}
	return res
}

func (m *Module) buildSecret(form readForm, w walkState, hit secretHit, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + hit.reqPath
	evidence := []string{
		"secret marker: " + hit.marker,
		"node: " + hit.path,
		"read primitive: DefaultGetServlet " + primitiveLabel(form),
	}
	if len(w.reached) > 0 {
		evidence = append(evidence, "nodes reached: "+strings.Join(capNodes(w.reached), ", "))
	}

	res := &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             aem.HostFromBase(baseURL),
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name: "AEM JCR Configuration Secret Disclosure",
			Description: fmt.Sprintf(
				"A JCR node readable without authentication (%s) exposes credential material (%s). AEM stores OSGi configuration — database passwords, cloud service keys, API tokens — as node properties, so an unauthenticated repository read leaks live secrets.",
				hit.path, hit.marker,
			),
			Severity:   severity.Critical,
			Confidence: severity.Firm,
			Tags:       append([]string{"aem", "adobe", "info-disclosure", "credential-exposure", "jcr"}, aem.ACLBypassTag(form.isBypass())...),
			Reference:  refs,
		},
	}
	if form.isBypass() {
		modkit.AnnotatePathBypassFinding(res, hit.reqPath)
	}
	return res
}

func (m *Module) buildUserEnum(form readForm, w walkState, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + w.userEnumReq
	evidence := []string{
		"node: " + w.userEnumPath,
		"read primitive: DefaultGetServlet " + primitiveLabel(form),
	}
	if w.userEnumID != "" {
		evidence = append(evidence, "sample account: "+w.userEnumID)
	}

	res := &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             aem.HostFromBase(baseURL),
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name: "AEM User Account Enumeration via JCR",
			Description: fmt.Sprintf(
				"The user store under %s is readable without authentication and exposes rep:User accounts (rep:authorizableId). AEM has no brute-force protection on Basic auth, so enumerated accounts feed a credential-guessing attack.",
				w.userEnumPath,
			),
			Severity:   severity.High,
			Confidence: severity.Firm,
			Tags:       append([]string{"aem", "adobe", "info-disclosure", "user-enumeration", "jcr"}, aem.ACLBypassTag(form.isBypass())...),
			Reference:  refs,
		},
	}
	if form.isBypass() {
		modkit.AnnotatePathBypassFinding(res, w.userEnumReq)
	}
	return res
}

func primitiveLabel(form readForm) string {
	if form.isBypass() {
		return "via dispatcher bypass (" + form.sample + ")"
	}
	return "direct (.1.json)"
}

func bypassClause(form readForm) string {
	if form.isBypass() {
		return ", reached through a dispatcher bypass"
	}
	return ""
}

func capNodes(nodes []string) []string {
	if len(nodes) <= maxEvidenceNodes {
		return nodes
	}
	out := append([]string{}, nodes[:maxEvidenceNodes]...)
	return append(out, fmt.Sprintf("… (+%d more)", len(nodes)-maxEvidenceNodes))
}
