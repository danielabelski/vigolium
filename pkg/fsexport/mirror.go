package fsexport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// mirrorBufferSize bounds how many save events can queue ahead of the disk
// writer before the mirror starts dropping (best-effort — the DB is unaffected).
const mirrorBufferSize = 2048

// Mirror incrementally writes ingested HTTP records and findings to a flat
// filesystem tree as they are persisted, so an external agent can read live
// traffic as files alongside the database. It is fed via OnRecord/OnFinding
// (wired to the repository's save callbacks) and does all disk I/O on a single
// background goroutine, so the DB save path never blocks. Indexes are
// append-only JSONL (one object per line) — friendly to a live, growing log and
// to `jq`/`grep`. Per-host ids resume from the existing tree on startup, so a
// restart continues numbering instead of overwriting.
//
// This is the live sibling of the one-shot `vigolium export --format fs` tree;
// the layouts match except the mirror writes index.jsonl (streaming) where the
// one-shot writes index.json (a final array), and the mirror leaves each traffic
// row's `finding` null (findings arrive after their record is written).
type Mirror struct {
	trafficRoot  string
	findingsRoot string
	omitResponse bool

	jobs chan mirrorJob
	wg   sync.WaitGroup

	mu     sync.Mutex
	closed bool

	// The fields below are touched only by the single run goroutine (after
	// resume(), which runs before it starts) — no lock needed.
	trafficSeq map[string]int
	findingSeq map[string]int
	// uuidToPath maps a record uuid → "host/id" so a later finding can cross-link
	// its traffic. Bounded (LRU) so a long-lived --mirror-fs server can't grow it
	// for every record ever mirrored; a finding referencing an evicted record just
	// renders without that link (graceful fallback in writeFinding).
	uuidToPath   *lru.Cache[string, string]
	trafficIndex *os.File
	findingIndex *os.File
}

// mirrorLinkCacheSize bounds the record-uuid → path link cache.
const mirrorLinkCacheSize = 100000

func newMirrorLinkCache() *lru.Cache[string, string] {
	c, _ := lru.New[string, string](mirrorLinkCacheSize)
	return c
}

type mirrorJob struct {
	record  *database.HTTPRecord
	finding *database.Finding
}

// NewMirror creates a filesystem mirror rooted at dir (writing dir/traffic and
// dir/findings) and starts its background writer. omitResponse drops the
// .resp.* files. The traffic root is created eagerly so a misconfigured path
// fails fast; the findings root is created lazily on the first finding.
func NewMirror(dir string, omitResponse bool) (*Mirror, error) {
	m := &Mirror{
		trafficRoot:  filepath.Join(dir, "traffic"),
		findingsRoot: filepath.Join(dir, "findings"),
		omitResponse: omitResponse,
		jobs:         make(chan mirrorJob, mirrorBufferSize),
		trafficSeq:   map[string]int{},
		findingSeq:   map[string]int{},
		uuidToPath:   newMirrorLinkCache(),
	}
	if err := os.MkdirAll(m.trafficRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create mirror dir %s: %w", m.trafficRoot, err)
	}
	m.resume()
	m.wg.Add(1)
	go m.run()
	return m, nil
}

// OnRecord queues a newly saved HTTP record for mirroring. Safe to call from any
// goroutine; never blocks the caller (drops when the buffer is full).
func (m *Mirror) OnRecord(rec *database.HTTPRecord) {
	if rec == nil {
		return
	}
	m.enqueue(mirrorJob{record: rec})
}

// OnFinding queues a newly saved finding for mirroring.
func (m *Mirror) OnFinding(f *database.Finding) {
	if f == nil {
		return
	}
	m.enqueue(mirrorJob{finding: f})
}

// enqueue offers a job to the writer without blocking the DB save path. The
// send happens under mu so it can never race Close()'s channel close.
func (m *Mirror) enqueue(j mirrorJob) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	select {
	case m.jobs <- j:
	default:
		zap.L().Warn("fsexport mirror buffer full, dropping job (database unaffected)")
	}
}

// Close stops accepting jobs, drains what's queued, and flushes the indexes.
func (m *Mirror) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	close(m.jobs)
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *Mirror) run() {
	defer m.wg.Done()
	for j := range m.jobs {
		if j.record != nil {
			m.writeRecord(j.record)
		}
		if j.finding != nil {
			m.writeFinding(j.finding)
		}
	}
	if m.trafficIndex != nil {
		_ = m.trafficIndex.Close()
	}
	if m.findingIndex != nil {
		_ = m.findingIndex.Close()
	}
}

func (m *Mirror) writeRecord(rec *database.HTTPRecord) {
	if len(rec.RawRequest) == 0 {
		return
	}
	host := SanitizeHost(rec.Hostname)
	dir := filepath.Join(m.trafficRoot, host)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		zap.L().Warn("fsexport mirror: create host dir", zap.Error(err))
		return
	}
	m.trafficSeq[host]++
	id := fmt.Sprintf("%04d", m.trafficSeq[host])

	if err := os.WriteFile(filepath.Join(dir, id+".req"), RequestBytes(rec), 0o644); err != nil {
		zap.L().Warn("fsexport mirror: write req", zap.Error(err))
		return
	}

	// Best-effort: a response write failure is logged but still indexed (the
	// .req landed), unlike the one-shot export which aborts.
	status, bodyLen, err := WriteResponseFiles(dir, id, rec, m.omitResponse)
	if err != nil {
		zap.L().Warn("fsexport mirror: write response", zap.Error(err))
	}

	relPath := host + "/" + id
	m.uuidToPath.Add(rec.UUID, relPath)
	m.appendIndex(&m.trafficIndex, filepath.Join(m.trafficRoot, "index.jsonl"), TrafficEntry{
		ID:          id,
		Host:        rec.Hostname,
		Path:        relPath,
		Method:      rec.Method,
		URL:         rec.Path,
		Status:      status,
		ContentType: CleanContentType(rec.ResponseContentType),
		Bytes:       bodyLen,
	})
}

func (m *Mirror) writeFinding(f *database.Finding) {
	host := SanitizeHost(FindingHost(f))
	dir := filepath.Join(m.findingsRoot, host)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		zap.L().Warn("fsexport mirror: create findings dir", zap.Error(err))
		return
	}
	m.findingSeq[host]++
	id := fmt.Sprintf("%04d", m.findingSeq[host])

	var linked []LinkedRecord
	var linkedPaths []string
	for _, u := range f.HTTPRecordUUIDs {
		if p, ok := m.uuidToPath.Get(u); ok {
			linked = append(linked, ReadLinkedRecord(m.trafficRoot, p, m.omitResponse))
			linkedPaths = append(linkedPaths, p)
		}
	}

	md := RenderFindingMarkdown(f, linked, "traffic")
	if err := os.WriteFile(filepath.Join(dir, id+".md"), md, 0o644); err != nil {
		zap.L().Warn("fsexport mirror: write finding", zap.Error(err))
		return
	}

	title := f.ModuleName
	if title == "" {
		title = f.ModuleID
	}
	m.appendIndex(&m.findingIndex, filepath.Join(m.findingsRoot, "index.jsonl"), FindingEntry{
		ID:         id,
		Host:       FindingHost(f),
		Path:       host + "/" + id + ".md",
		Severity:   f.Severity,
		Confidence: f.Confidence,
		Module:     f.ModuleID,
		Title:      title,
		URL:        f.URL,
		Traffic:    linkedPaths,
	})
}

// appendIndex appends one JSON line to the index file at path, opening (in
// append mode) and caching the handle on *fp on first use.
func (m *Mirror) appendIndex(fp **os.File, path string, entry any) {
	if *fp == nil {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			zap.L().Warn("fsexport mirror: open index", zap.Error(err))
			return
		}
		*fp = f
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')
	if _, err := (*fp).Write(data); err != nil {
		zap.L().Warn("fsexport mirror: write index", zap.Error(err))
	}
}

// resume rebuilds the per-host sequence counters from any tree left by a prior
// run, so a restart continues numbering (e.g. resumes at 0007 if 0006.req is the
// highest on disk) instead of overwriting existing files. uuid→path links are
// not recoverable from filenames, so findings in a new session only link to
// records ingested in that same session (older links fall back to inline
// request/response in the finding markdown).
func (m *Mirror) resume() {
	m.trafficSeq = scanMaxSeq(m.trafficRoot, ".req")
	m.findingSeq = scanMaxSeq(m.findingsRoot, ".md")
}

// scanMaxSeq returns, per host dir under root, the highest numeric id of files
// ending in suffix (e.g. "0006.req" → 6). Missing roots yield an empty map.
func scanMaxSeq(root, suffix string) map[string]int {
	out := map[string]int{}
	hosts, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, h := range hosts {
		if !h.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, h.Name()))
		if err != nil {
			continue
		}
		max := 0
		for _, fi := range files {
			name := fi.Name()
			if !strings.HasSuffix(name, suffix) {
				continue
			}
			if n, err := strconv.Atoi(strings.TrimSuffix(name, suffix)); err == nil && n > max {
				max = n
			}
		}
		if max > 0 {
			out[h.Name()] = max
		}
	}
	return out
}
