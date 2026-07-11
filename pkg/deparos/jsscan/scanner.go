package jsscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Scanner provides the jsscan analysis API.
// Thread-safe for concurrent use.
type Scanner struct {
	mu           sync.RWMutex
	extractor    *Extractor
	config       *Config
	binary       *CachedBinary
	capabilities *Capabilities
	sem          chan struct{}

	// bufPool recycles stdout/stderr buffers across subprocess invocations.
	bufPool sync.Pool
}

// NewScanner creates a new Scanner with the given configuration.
// The jsscan binary is extracted lazily on first scan.
func NewScanner(config *Config) (*Scanner, error) {
	if config == nil {
		config = DefaultConfig()
	}

	extractor, err := NewExtractor(config)
	if err != nil {
		return nil, fmt.Errorf("create extractor: %w", err)
	}

	s := &Scanner{
		extractor: extractor,
		config:    config,
		sem:       make(chan struct{}, max(1, config.MaxConcurrent)),
	}
	cleanupStaleTempFiles()

	s.bufPool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, 64*1024)) // 64 KiB initial
		},
	}

	return s, nil
}

// acquireTmpFile returns a uniquely owned temporary input path. Inputs are not
// pooled: sync.Pool cannot be enumerated or deterministically cleaned at Close.
func (s *Scanner) acquireTmpFile() (string, error) {
	f, err := os.CreateTemp("", "jsscan-*.js")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	path := f.Name()
	_ = f.Close()
	return path, nil
}

var staleCleanupOnce sync.Once

func cleanupStaleTempFiles() {
	staleCleanupOnce.Do(func() {
		entries, err := os.ReadDir(os.TempDir())
		if err != nil {
			return
		}
		cutoff := time.Now().Add(-24 * time.Hour)
		for _, entry := range entries {
			name := entry.Name()
			isJobDir := entry.IsDir() && strings.HasPrefix(name, "jsscan-job-")
			isTempFile := !entry.IsDir() && (strings.HasPrefix(name, "jsscan-") || strings.HasPrefix(name, "jsscan-out-"))
			if !isJobDir && !isTempFile {
				continue
			}
			info, statErr := entry.Info()
			if statErr == nil && info.ModTime().Before(cutoff) {
				_ = os.RemoveAll(filepath.Join(os.TempDir(), name))
			}
		}
	})
}

// Scan analyzes the provided JavaScript content.
// This is the main API entry point for the jsscan package.
//
// The function:
// 1. Ensures the jsscan binary is available (extracts if needed)
// 2. Writes content to a pooled temporary file
// 3. Executes jsscan binary with the temp file
// 4. Parses and returns the findings
//
// Thread-safe for concurrent calls.
func (s *Scanner) Scan(ctx context.Context, content []byte) (*ScanResult, error) {
	return s.ScanWithOptions(ctx, content, ScanOptions{Profile: ProfileLegacy})
}

// ScanWithOptions analyzes the provided JavaScript content with the given
// options (e.g. Beautify). Scan is the zero-options convenience wrapper.
// Thread-safe for concurrent calls.
func (s *Scanner) ScanWithOptions(ctx context.Context, content []byte, opts ScanOptions) (*ScanResult, error) {
	opts = normalizeScanOptions(opts)
	if len(content) == 0 {
		return &ScanResult{
			Requests:     []ExtractedRequest{},
			BytesScanned: 0,
		}, nil
	}
	if len(content) > opts.MaxInputBytes {
		return nil, fmt.Errorf("%w: input=%d limit=%d", ErrInputTooLarge, len(content), opts.MaxInputBytes)
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	startTime := time.Now()

	binary, err := s.getBinary()
	if err != nil {
		return nil, err
	}

	tmpPath, err := s.acquireTmpFile()
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmpPath) }()

	// Truncate and rewrite — avoids creating a new inode each time
	if err := os.WriteFile(tmpPath, content, 0600); err != nil {
		return nil, fmt.Errorf("write temp file: %w", err)
	}

	result, err := s.executeJsscan(ctx, binary.Path, tmpPath, opts)
	if err != nil {
		return nil, err
	}
	result.ScanDuration = time.Since(startTime)
	result.BytesScanned = len(content)
	return result, nil
}

// ScanFile scans a file directly without copying to temp file.
// Useful for scanning large files efficiently.
func (s *Scanner) ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	startTime := time.Now()
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	binary, err := s.getBinary()
	if err != nil {
		return nil, err
	}

	opts := normalizeScanOptions(ScanOptions{Profile: ProfileLegacy})
	if info.Size() > int64(opts.MaxInputBytes) {
		return nil, fmt.Errorf("%w: input=%d limit=%d", ErrInputTooLarge, info.Size(), opts.MaxInputBytes)
	}
	result, err := s.executeJsscan(ctx, binary.Path, filePath, opts)
	if err != nil {
		return nil, err
	}
	result.ScanDuration = time.Since(startTime)
	result.BytesScanned = int(info.Size())
	return result, nil
}

func normalizeScanOptions(opts ScanOptions) ScanOptions {
	if opts.Profile == "" {
		opts.Profile = ProfileLegacy
	}
	if opts.MaxInputBytes <= 0 {
		opts.MaxInputBytes = DefaultMaxInputBytes
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if opts.MaxArtifactBytes <= 0 {
		opts.MaxArtifactBytes = DefaultMaxArtifactBytes
	}
	if opts.MaxRequests <= 0 {
		opts.MaxRequests = 1000
	}
	if opts.MaxASTNodes <= 0 {
		opts.MaxASTNodes = DefaultMaxASTNodes
	}
	if opts.Deadline <= 0 {
		opts.Deadline = 60 * time.Second
	}
	return opts
}

// ScanReader scans content from an io.Reader.
// Reads all content into memory before scanning.
func (s *Scanner) ScanReader(ctx context.Context, r io.Reader) (*ScanResult, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read content: %w", err)
	}
	return s.Scan(ctx, content)
}

// getBinary returns the cached binary or extracts it.
// Uses double-check locking pattern.
func (s *Scanner) getBinary() (*CachedBinary, error) {
	s.mu.RLock()
	if s.binary != nil {
		binary := s.binary
		s.mu.RUnlock()
		return binary, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.binary != nil {
		return s.binary, nil
	}

	binary, err := s.extractor.GetBinary()
	if err != nil {
		return nil, err
	}

	caps, err := queryCapabilities(binary.Path)
	if err != nil {
		return nil, err
	}
	if caps.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("%w: helper=%d client=%d", ErrIncompatibleProtocol, caps.ProtocolVersion, ProtocolVersion)
	}

	s.binary = binary
	s.capabilities = caps
	return binary, nil
}

func queryCapabilities(binaryPath string) (*Capabilities, error) {
	// First launch of a freshly extracted standalone Bun executable can include
	// platform signature/quarantine checks. Keep this bounded, but do not treat a
	// normal cold start as a protocol failure.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, "--capabilities")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: query capabilities: %v", ErrIncompatibleProtocol, err)
	}
	if len(output) > 1024*1024 {
		return nil, fmt.Errorf("%w: capability output too large", ErrIncompatibleProtocol)
	}
	var caps Capabilities
	if err := json.Unmarshal(bytes.TrimSpace(output), &caps); err != nil {
		return nil, fmt.Errorf("%w: decode capabilities: %v", ErrIncompatibleProtocol, err)
	}
	if caps.Type != "capabilities" || caps.SourceHash == "" {
		return nil, fmt.Errorf("%w: invalid capability record", ErrIncompatibleProtocol)
	}
	return &caps, nil
}

// executeJsscan runs the jsscan binary and parses output.
// Uses a pooled buffer for stderr to reduce GC pressure.
func (s *Scanner) executeJsscan(ctx context.Context, binaryPath, inputPath string, opts ScanOptions) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, MaxScanTimeout)
	defer cancel()

	s.mu.RLock()
	caps := s.capabilities
	s.mu.RUnlock()
	if caps == nil || !slices.Contains(caps.Profiles, string(opts.Profile)) {
		return nil, fmt.Errorf("%w: profile %q unsupported", ErrIncompatibleProtocol, opts.Profile)
	}

	jobDir, err := os.MkdirTemp("", "jsscan-job-*")
	if err != nil {
		return nil, fmt.Errorf("create jsscan job directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(jobDir) }()

	args := make([]string, 0, 20)
	if opts.Beautify {
		args = append(args, "--beautify")
	}
	args = append(args,
		"--protocol", "2",
		"--artifact-dir", jobDir,
		"--profile", string(opts.Profile),
		"--max-requests", fmt.Sprintf("%d", opts.MaxRequests),
		"--max-ast-nodes", fmt.Sprintf("%d", opts.MaxASTNodes),
		"--max-output-bytes", fmt.Sprintf("%d", opts.MaxOutputBytes),
		"--max-artifact-bytes", fmt.Sprintf("%d", opts.MaxArtifactBytes),
		"--deadline-ms", fmt.Sprintf("%d", opts.Deadline.Milliseconds()),
	)
	if opts.SourceURL != "" {
		args = append(args, "--source-url", opts.SourceURL)
	}
	if opts.Filename != "" {
		args = append(args, "--source-name", opts.Filename)
	}
	if opts.MediaType != "" {
		args = append(args, "--media-type", opts.MediaType)
	}
	args = append(args, inputPath)
	cmd := exec.CommandContext(ctx, binaryPath, args...)

	// Capture stdout in a temp FILE rather than a pipe (bytes.Buffer). jsscan is a
	// Bun/Node runtime that emits one JSONL record per line; the `code` and
	// `beautified` records for a large bundle exceed 64KB. Node/Bun writes stdout
	// asynchronously when it is a pipe and can exit before the tail of a large write
	// has drained through the ~64KB kernel pipe buffer, silently truncating those
	// records — the truncated JSON then fails to parse and the beautified document is
	// lost. A regular file is always write-ready (synchronous, no pipe-buffer cap),
	// so the full output survives regardless of line size.
	outFile, err := os.CreateTemp("", "jsscan-out-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("create output temp file: %w", err)
	}
	outPath := outFile.Name()
	defer func() {
		_ = os.Remove(outPath)
	}()

	stderr := s.bufPool.Get().(*bytes.Buffer)
	stderr.Reset()
	defer s.bufPool.Put(stderr)
	boundedStderr := &cappedBuffer{buffer: stderr, max: 64 * 1024}

	cmd.Stdout = outFile
	cmd.Stderr = boundedStderr

	if err := cmd.Start(); err != nil {
		_ = outFile.Close()
		return nil, fmt.Errorf("%w: start helper: %v", ErrScanFailed, err)
	}
	var outputExceeded atomic.Bool
	monitorDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if info, statErr := outFile.Stat(); statErr == nil && info.Size() > opts.MaxOutputBytes+1024*1024 {
					outputExceeded.Store(true)
					_ = cmd.Process.Kill()
					return
				}
			case <-monitorDone:
				return
			}
		}
	}()
	runErr := cmd.Wait()
	close(monitorDone)
	_ = outFile.Close()

	if outputExceeded.Load() {
		return nil, fmt.Errorf("%w: limit=%d", ErrOutputTooLarge, opts.MaxOutputBytes)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if info, statErr := os.Stat(outPath); statErr == nil && info.Size() > opts.MaxOutputBytes+1024*1024 {
		return nil, fmt.Errorf("%w: output=%d limit=%d", ErrOutputTooLarge, info.Size(), opts.MaxOutputBytes)
	}

	output, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read jsscan output: %w", err)
	}

	result := parseJsscanOutput(output)
	if runErr != nil {
		return nil, fmt.Errorf("%w: %v, stderr: %s", ErrScanFailed, runErr, stderr.String())
	}
	if result.MalformedRecords > 0 {
		return nil, fmt.Errorf("%w: %d malformed record(s)", ErrIncompleteOutput, result.MalformedRecords)
	}
	if result.Completion == nil {
		return nil, fmt.Errorf("%w: missing scanCompleted record", ErrIncompleteOutput)
	}
	if result.Completion.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("%w: completion protocol=%d", ErrIncompatibleProtocol, result.Completion.ProtocolVersion)
	}
	if result.Analysis == nil {
		return nil, fmt.Errorf("%w: missing analysisResult v2 envelope", ErrIncompleteOutput)
	}
	if result.Analysis.SchemaVersion != 2 || result.Analysis.JobID != result.Completion.ScanID {
		return nil, fmt.Errorf("%w: inconsistent v2 envelope", ErrIncompleteOutput)
	}
	if caps != nil && result.Analysis.Tool.SourceHash != caps.SourceHash {
		return nil, fmt.Errorf("%w: result source hash differs from capability handshake", ErrIncompatibleProtocol)
	}
	if err := loadArtifacts(result, jobDir, opts.MaxArtifactBytes); err != nil {
		return nil, err
	}
	if result.Completion.Status == "failed" || result.Completion.Status == "cancelled" {
		return nil, fmt.Errorf("%w: status=%s reason=%s", ErrScanFailed, result.Completion.Status, result.Completion.ReasonCode)
	}
	return result, nil
}

func loadArtifacts(result *ScanResult, jobDir string, maxArtifactBytes int64) error {
	root, err := filepath.Abs(jobDir)
	if err != nil {
		return fmt.Errorf("resolve artifact directory: %w", err)
	}
	if evaluated, evalErr := filepath.EvalSymlinks(root); evalErr == nil {
		root = evaluated
	}
	for i := range result.Artifacts {
		artifact := &result.Artifacts[i]
		path, err := filepath.Abs(artifact.Path)
		if err != nil {
			return fmt.Errorf("resolve artifact path: %w", err)
		}
		if evaluated, evalErr := filepath.EvalSymlinks(path); evalErr == nil {
			path = evaluated
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return fmt.Errorf("%w: artifact path escapes job directory", ErrScanFailed)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("read artifact metadata: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: artifact is not a regular file", ErrScanFailed)
		}
		if info.Size() != artifact.ByteLength || info.Size() < 0 || info.Size() > maxArtifactBytes {
			return fmt.Errorf("%w: invalid artifact size %d", ErrOutputTooLarge, info.Size())
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read artifact: %w", err)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(content))
		if !strings.EqualFold(digest, artifact.SHA256) {
			return fmt.Errorf("%w: artifact checksum mismatch", ErrScanFailed)
		}
		artifact.Content = content
		artifact.Path = ""
		switch artifact.ArtifactType {
		case "transformedSource":
			result.Code = &CodeRecord{Filename: artifact.Filename, Content: string(content)}
		case "beautifiedSource":
			result.Beautified = &BeautifiedCode{
				Filename: artifact.Filename, Format: artifact.Format,
				ModuleCount: artifact.ModuleCount, ModulePaths: artifact.ModulePaths,
				Changed: true, Content: string(content),
			}
		}
	}
	if result.Analysis != nil {
		for i := range result.Analysis.Artifacts {
			result.Analysis.Artifacts[i].Path = ""
		}
	}
	return nil
}

type cappedBuffer struct {
	buffer    *bytes.Buffer
	max       int
	truncated bool
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := w.max - w.buffer.Len()
	if remaining <= 0 {
		w.truncated = true
		return original, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		w.truncated = true
	}
	_, _ = w.buffer.Write(p)
	return original, nil
}

// rawRecord is used to detect the type field before full parsing.
type rawRecord struct {
	Type string `json:"type"`
}

// parseJsscanOutput parses the JSONL output from jsscan into a ScanResult.
// jsscan outputs one JSON object per line (JSONL format). Supports record types:
// 'extractedRequest', 'code', 'domFlow', and (under --beautify) 'beautified'.
// ScanDuration/BytesScanned are filled in by the caller.
func parseJsscanOutput(output []byte) *ScanResult {
	result := &ScanResult{Requests: []ExtractedRequest{}}
	if len(output) == 0 {
		return result
	}

	lines := bytes.Split(output, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var raw rawRecord
		if err := json.Unmarshal(line, &raw); err != nil {
			result.MalformedRecords++
			continue
		}

		switch raw.Type {
		case "analysisResult":
			var analysis AnalysisResultV2
			if err := json.Unmarshal(line, &analysis); err != nil {
				result.MalformedRecords++
				continue
			}
			result.Analysis = &analysis
			result.Diagnostics = append(result.Diagnostics, analysis.Diagnostics...)
			result.Artifacts = append(result.Artifacts, analysis.Artifacts...)
			for _, record := range analysis.Records {
				appendAnalysisRecord(result, record)
			}
		case "extractedRequest":
			var req ExtractedRequest
			if err := json.Unmarshal(line, &req); err != nil {
				result.MalformedRecords++
				continue
			}
			result.Requests = append(result.Requests, req)
		case "code":
			var c CodeRecord
			if err := json.Unmarshal(line, &c); err != nil {
				result.MalformedRecords++
				continue
			}
			result.Code = &c
		case "domFlow":
			var f DomFlow
			if err := json.Unmarshal(line, &f); err != nil {
				result.MalformedRecords++
				continue
			}
			result.DomFlows = append(result.DomFlows, f)
		case "beautified":
			var b BeautifiedCode
			if err := json.Unmarshal(line, &b); err != nil {
				result.MalformedRecords++
				continue
			}
			result.Beautified = &b
		case "diagnostic":
			var diagnostic Diagnostic
			if err := json.Unmarshal(line, &diagnostic); err != nil {
				result.MalformedRecords++
				continue
			}
			result.Diagnostics = append(result.Diagnostics, diagnostic)
		case "scanCompleted":
			var completion ScanCompletion
			if err := json.Unmarshal(line, &completion); err != nil {
				result.MalformedRecords++
				continue
			}
			result.Completion = &completion
		case "scanStarted", "requestPattern":
			// Recognized control/evidence records are intentionally not retained by
			// the compact Go result.
		default:
			result.UnknownRecords++
			result.appendUnknownRecord(line)
		}
	}

	return result
}

// appendAnalysisRecord is shared by the compatibility JSONL decoder and the
// persistent framed worker decoder so every protocol-v2 record family has one
// parsing policy.
func appendAnalysisRecord(result *ScanResult, record json.RawMessage) {
	var kind struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(record, &kind); err != nil {
		result.MalformedRecords++
		return
	}
	decode := func(target any) bool {
		if err := json.Unmarshal(record, target); err != nil {
			result.MalformedRecords++
			return false
		}
		return true
	}
	switch kind.Kind {
	case "httpRequest":
		var fact HTTPRequestFact
		if decode(&fact) {
			result.RequestFacts = append(result.RequestFacts, fact)
			result.Requests = append(result.Requests, legacyRequestFromFact(fact))
		}
	case "domFlow":
		var fact DomFlowFact
		if decode(&fact) {
			result.DomFlowFacts = append(result.DomFlowFacts, fact)
			result.DomFlows = append(result.DomFlows, DomFlow{
				FlowType: fact.FlowType, Source: fact.Source, Sink: fact.Sink,
				Snippet: fact.Snippet, Line: fact.Line,
			})
		}
	case "assetReference":
		var fact AssetReferenceFact
		if decode(&fact) {
			result.AssetFacts = append(result.AssetFacts, fact)
		}
	case "graphqlOperation":
		var fact GraphQLOperationFact
		if decode(&fact) {
			result.GraphQLOperations = append(result.GraphQLOperations, fact)
		}
	case "websocket":
		var fact WebSocketFact
		if decode(&fact) {
			result.WebSockets = append(result.WebSockets, fact)
		}
	case "eventSource":
		var fact EventSourceFact
		if decode(&fact) {
			result.EventSources = append(result.EventSources, fact)
		}
	case "clientRoute":
		var fact ClientRouteFact
		if decode(&fact) {
			result.ClientRoutes = append(result.ClientRoutes, fact)
		}
	case "browserSecurityFlow":
		var fact BrowserSecurityFlowFact
		if decode(&fact) {
			result.BrowserFlows = append(result.BrowserFlows, fact)
		}
	default:
		result.UnknownRecords++
		result.appendUnknownRecord(record)
	}
}

func (r *ScanResult) appendUnknownRecord(record []byte) {
	r.UnknownRecordData = append(r.UnknownRecordData, json.RawMessage(append([]byte(nil), record...)))
}

func renderFieldTemplates(fields []FieldTemplate) string {
	var b strings.Builder
	for i, field := range fields {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(field.Name.Rendered)
		b.WriteByte('=')
		b.WriteString(field.Value.Rendered)
	}
	return b.String()
}

func legacyRequestFromFact(fact HTTPRequestFact) ExtractedRequest {
	headers := make([]string, 0, len(fact.Headers))
	for _, header := range fact.Headers {
		headers = append(headers, header.Name.Rendered+": "+header.Value.Rendered)
	}
	cookies := make([]string, 0, len(fact.Cookies))
	for _, cookie := range fact.Cookies {
		cookies = append(cookies, cookie.Name.Rendered+"="+cookie.Value.Rendered)
	}
	body := ""
	if fact.Body != nil {
		body = fact.Body.Value.Rendered
	}
	return ExtractedRequest{
		URL: fact.URL.Rendered, Method: fact.Method.Rendered,
		Params: renderFieldTemplates(fact.Query), Body: body,
		Headers: headers, Cookies: cookies,
	}
}

// LegacyRequestFromFact projects a typed v2 fact into the v1 compatibility
// shape. New replay code should retain the original fact alongside this view.
func LegacyRequestFromFact(fact HTTPRequestFact) ExtractedRequest {
	return legacyRequestFromFact(fact)
}

// Checksum returns the checksum of the cached/extracted jsscan binary.
// Returns empty string if not yet extracted.
func (s *Scanner) Checksum() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.binary == nil {
		return ""
	}
	return s.binary.Checksum
}

// EnsureBinary pre-extracts the binary if not already cached.
// Useful for initialization to avoid delay on first scan.
func (s *Scanner) EnsureBinary() error {
	_, err := s.getBinary()
	return err
}

// Capabilities validates the helper and returns a defensive copy of its
// negotiated protocol metadata.
func (s *Scanner) Capabilities() (*Capabilities, error) {
	if _, err := s.getBinary(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.capabilities == nil {
		return nil, ErrIncompatibleProtocol
	}
	copy := *s.capabilities
	copy.Capabilities = append([]string(nil), s.capabilities.Capabilities...)
	copy.Profiles = append([]string(nil), s.capabilities.Profiles...)
	copy.Framing = append([]string(nil), s.capabilities.Framing...)
	return &copy, nil
}

// Clear removes the cached binary and forces re-extraction on next scan.
func (s *Scanner) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.binary = nil
	s.capabilities = nil
	return s.extractor.Clear()
}

// Close satisfies lifecycle-oriented callers. Scanner owns no long-lived
// subprocess or input path; each invocation removes its files synchronously.
// Persistent workers are owned and closed by Service.
func (s *Scanner) Close() error { return nil }

// BinaryPath returns the path to the jsscan binary.
// Returns empty string if not yet extracted.
func (s *Scanner) BinaryPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.binary == nil {
		return ""
	}
	return s.binary.Path
}
