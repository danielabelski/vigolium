package cli

import (
	"fmt"
	"os"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/jsext"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// buildJSEvalOptions assembles the jsext API surface shared by the two
// ad-hoc JavaScript entry points, `vigolium js` and `vigolium extensions
// eval`. Both used to build this independently and drifted: eval never
// constructed an HTTP requester, and because jsext's shouldRegisterNS
// gates whole namespaces on the options it is handed, that silently
// dropped `vigolium.http` and `vigolium.mcp` from a command whose own
// help promised the full API surface. Keeping one builder is what stops
// a capability added to one door from going missing at the other.
//
// The returned cleanup is always non-nil when err is nil and must be
// deferred by the caller; it releases the HTTP stack and the database
// handle in reverse order of acquisition.
func buildJSEvalOptions(scriptID string, settings *config.Settings) (jsext.APIOptions, func(), error) {
	opts := jsext.APIOptions{
		ScriptID:    scriptID,
		ConfigVars:  settings.DynamicAssessment.Extensions.Variables,
		AllowExec:   settings.DynamicAssessment.Extensions.AllowExec,
		SandboxDir:  config.ExpandPath(settings.DynamicAssessment.Extensions.SandboxDir),
		ExecTimeout: settings.DynamicAssessment.Extensions.ExecTimeout(),
	}

	var cleanups []func()
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	// The database is genuinely optional: without it vigolium.db and
	// vigolium.ingest stay unregistered, which is a coherent subset
	// rather than a broken VM, so a failure here is not fatal.
	if db, err := getDB(); err == nil && db != nil {
		cleanups = append(cleanups, closeDatabaseOnExit)
		opts.Repository = database.NewRepository(db)
		if projUUID, projErr := resolveProjectUUID(); projErr == nil {
			opts.ProjectUUID = projUUID
		}
	}

	if settings.Scope.Host.Include != nil || settings.Scope.Path.Include != nil {
		opts.ScopeMatcher = config.NewScopeMatcher(settings.Scope)
		opts.ScopeConfig = &settings.Scope
	}

	// The HTTP stack gates vigolium.http and vigolium.mcp. A failure is
	// not fatal - a pure-computation script still runs - but it must not
	// be silent, because the symptom at the other end is an undefined
	// namespace rather than an error anyone can trace back to here.
	requester, httpCleanup, err := setupJsHTTPStack(settings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s HTTP stack unavailable (%v); vigolium.http and vigolium.mcp will not be registered\n",
			terminal.WarningSymbol(), err)
		return opts, cleanup, nil
	}
	cleanups = append(cleanups, httpCleanup)
	opts.HTTPClient = requester

	return opts, cleanup, nil
}
