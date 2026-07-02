package discovery

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/deparos/config"
	pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"
	"github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/deparos/wordlist"
	"go.uber.org/zap"
)

// State represents the discovery engine lifecycle state.
type State int

const (
	// StateIdle indicates engine hasn't started
	StateIdle State = iota
	// StateRunning indicates active discovery
	StateRunning
	// StatePaused indicates user-paused discovery
	StatePaused
	// StateStopped indicates terminated session (terminal state)
	StateStopped
)

// String returns human-readable state name.
func (s State) String() string {
	switch s {
	case StateIdle:
		return "IDLE"
	case StateRunning:
		return "RUNNING"
	case StatePaused:
		return "PAUSED"
	case StateStopped:
		return "STOPPED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

// collectDirectoryURLs walks directories and returns their URLs.
func collectDirectoryURLs(s storage.Storage) []string {
	urls := make([]string, 0, 1000)
	_ = s.WalkDirectories(func(node *storage.DiscoveredNode) error {
		urls = append(urls, node.URL().String())
		return nil
	})
	return urls
}

// extractFilenamesFromSitemap extracts filenames and extensions from existing sitemap URLs.
func extractFilenamesFromSitemap(e *Engine) error {
	return e.storage.WalkFiles(func(node *storage.DiscoveredNode) error {
		// Names/paths are always harvested for discovery. The observed-extension
		// confirmation (which triggers wordlist fuzzing) is gated on the stored
		// node having actually been served, so a crawled-but-not-served path such
		// as a dead /citation.cfm <a href> (404, or a redirect to a login/SPA
		// shell) does not confirm ".cfm". Stored nodes carry only a status code,
		// not the live analyzer's soft-404 verdict, so this is a status-based
		// approximation of the served gate the live path applies (OnFileDiscovered).
		e.applyFileMetadata(node.URL().Path, 0, nodeServedConfirmsExtension(node))
		return nil
	})
}

// nodeServedConfirmsExtension reports whether a stored node was served
// convincingly enough to treat its URL's extension as a real server-side route.
// A genuine 2xx, or an auth wall (401/403) that proves the handler exists,
// qualifies. A 3xx/404/5xx, or a node with no recorded response, does not — those
// are no proof the server serves that extension.
func nodeServedConfirmsExtension(node *storage.DiscoveredNode) bool {
	resp := node.Response()
	if resp == nil {
		return false
	}
	return statusConfirmsServedExtension(resp.StatusCode)
}

// statusConfirmsServedExtension reports whether an HTTP status proves the
// requested URL's server-side extension actually ran: a 2xx success, or a 401/403
// auth wall (the handler exists but gates access). A 3xx/404/5xx — or an unknown 0
// — does not: the request was redirected away, missing, or errored, so its
// extension is no evidence the server serves that stack. A recon-seeded probe path
// such as /Telerik.Web.UI.DialogHandler.aspx that a host 404s or 302s must not, on
// the strength of its ".aspx" suffix alone, confirm ASP.NET and queue a fuzz.
func statusConfirmsServedExtension(status int) bool {
	return pkghttp.IsSuccessStatus(status) || pkghttp.IsUnauthorized(status)
}

// applyFileMetadata extracts all file metadata from urlPath in a single pass
// and applies it to the engine's observed collections. This consolidates the
// duplicate extraction logic previously spread across extractFilenamesFromSitemap,
// extractFileMetadata, and collectValidatedLinks.
// confirmObserved gates the "observed" server-side extension confirmation
// (wordlist fuzzing): when false, names/paths/segments are still harvested but
// the URL's extension is not treated as proof the server serves that route.
// Callers tied to genuinely-served resources (sitemap, post-fetch file
// discovery) pass true; spider links pass extensionConfirmAllowed.
func (e *Engine) applyFileMetadata(urlPath string, depth uint16, confirmObserved bool) (meta FileMetadata) {
	meta = ExtractAllFileMetadata(urlPath)

	if meta.Name != "" {
		e.AddObservedNameTrusted(meta.Name)
	}
	if meta.Extension != "" {
		e.observeExtensionForFuzz(meta.Extension, urlPath, depth, true, confirmObserved)
	}

	// Store full filename for literal file testing (preserves hashes like app.b5ca88ec.js)
	if meta.RawFilename != "" && meta.RawExtension != "" {
		if _, ok := config.AllowedObservedExtensions[meta.RawExtension]; ok {
			e.AddObservedFileTrusted(meta.RawFilename)
		}
	}

	// Extract paths and segments
	if e.config.Filenames.UseObservedPaths {
		if meta.FuzzPath != "" {
			e.AddObservedPathTrusted(meta.FuzzPath)
		}
		for _, segment := range meta.Segments {
			segName, segExt := ExtractFilename("/" + segment)
			if segName != "" {
				e.AddObservedNameTrusted(segName)
			}
			if segExt != "" {
				e.observeExtensionForFuzz(segExt, urlPath, depth, false, confirmObserved)
			}
		}
	}

	return meta
}

// extractWordsFromResponses extracts words from stored response bodies.
// Returns count of words extracted.
func extractWordsFromResponses(e *Engine) int {
	count := 0
	_ = e.storage.WalkFiles(func(node *storage.DiscoveredNode) error {
		resp := node.Response()
		if resp == nil || len(resp.Body) == 0 {
			return nil
		}

		contentType := resp.MIMEType

		err := e.wordlistExtractor.ExtractBytes(
			e.ctx,
			resp.Body,
			contentType,
			func(token *wordlist.Token) {
				e.AddObservedName(token.Value)
				count++
			},
		)

		if err != nil {
			logger.Debug("Word extraction failed for stored response",
				zap.String("url", node.URL().String()),
				zap.Error(err))
		}

		return nil
	})
	return count
}

// addTasks adds multiple tasks and returns count of successfully added tasks.
// Deduplication happens in AddTask().
func (e *Engine) addTasks(tasks []Task) int {
	added := 0
	for _, task := range tasks {
		if e.AddTask(task) {
			added++
		}
	}
	return added
}

// incrementTasksBlocked atomically increments the TasksBlocked metric.
func (e *Engine) incrementTasksBlocked() {
	e.metricsMu.Lock()
	e.metrics.TasksBlocked++
	e.metricsMu.Unlock()
}

// incrementTasksDeduped atomically increments the TasksDeduped metric and returns new count.
func (e *Engine) incrementTasksDeduped() uint64 {
	e.metricsMu.Lock()
	e.metrics.TasksDeduped++
	count := e.metrics.TasksDeduped
	e.metricsMu.Unlock()
	return count
}

// incrementTasksGenerated atomically increments the TasksGenerated metric and returns new count.
func (e *Engine) incrementTasksGenerated() uint64 {
	e.metricsMu.Lock()
	e.metrics.TasksGenerated++
	count := e.metrics.TasksGenerated
	e.metricsMu.Unlock()
	return count
}

// observeExtensionForFuzz routes an extension seen in a real URL through the
// correct pipeline. Under ConfirmRequired it acts as the "observed"
// confirmation source (gated by ConfirmViaObserved); otherwise it preserves the
// legacy observed-extension behaviour. primary marks the URL's own last-segment
// extension, which in legacy mode could directly generate dynamic tasks at
// depth>0; segment-derived extensions never did. confirmObserved=false
// suppresses the observed confirmation entirely (untrusted source / SPA).
func (e *Engine) observeExtensionForFuzz(ext, urlPath string, depth uint16, primary, confirmObserved bool) {
	if e.config.Extensions.ConfirmRequired {
		if confirmObserved && e.config.Extensions.ConfirmViaObserved {
			e.confirmExtension(ext, "observed", urlPath, depth)
		}
		return
	}
	if !confirmObserved {
		return
	}
	if primary && depth > 0 {
		e.handleNewExtension(ext, depth)
		return
	}
	e.addObservedExtensionIfNew(ext)
}

// handleNewExtension processes a newly discovered extension.
// Adds to observed collections and generates dynamic tasks if configured.
func (e *Engine) handleNewExtension(ext string, depth uint16) {
	wasNew := e.addObservedExtensionIfNew(ext)
	if wasNew && e.config.Extensions.TestObserved {
		logger.Info("New extension discovered, generating dynamic tasks",
			zap.String("extension", ext))
		e.generateObservedExtensionTasks(ext, depth)
	}
}

// getObservedExtensionsSnapshot returns a snapshot of all seen extensions.
func (e *Engine) getObservedExtensionsSnapshot() []string {
	return e.observedExtensions.GetAllItems()
}
