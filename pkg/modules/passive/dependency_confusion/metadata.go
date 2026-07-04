package dependency_confusion

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "dependency-confusion"
	ModuleName  = "Dependency Confusion Candidate"
	ModuleShort = "Flags referenced npm package names that are unclaimed on the public registry"
)

var (
	ModuleDesc = `**What it means:** A scoped npm package (` + "`@org/name`" + `) imported by the target's JavaScript is not registered on the public registry (404). An unowned dependency name is the precondition for dependency confusion.

**How it's exploited:** If the build installs from the public registry without pinning this name, an attacker can publish a malicious package under it at a higher version and get it pulled into the build — code execution in CI/CD.

**Fix:** Claim the name publicly, scope internal packages to a private registry, and pin resolution (` + "`.npmrc`" + ` scope mapping, frozen lockfile).`

	ModuleConfirmation = "Suspected when a scoped package name imported by the target's JavaScript returns HTTP 404 from https://registry.npmjs.org (unclaimed). This is a heuristic — the app may resolve the name via a private registry, so the finding is Suspect/Tentative pending manual confirmation of the resolution source."
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"dependency-confusion", "supply-chain", "source-analysis", "npm"}
)
