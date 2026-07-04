package iis_shortname_discovery

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "iis-shortname-discovery"
	ModuleName  = "IIS Short Filename Discovery"
	ModuleShort = "Enumerates IIS 8.3 short filenames via tilde-based oracle (per-host)"
)

var (
	ModuleDesc = `**What it means:** IIS leaks partial filenames because 8.3 short-name (tilde) generation is enabled; wildcard tilde paths return differential status codes exposing a file's first six characters and extension. The scanner reconstructs full names by matching fragments against a wordlist via Windows' short-name and checksum algorithms, confirms each guess through independent oracles, recurses into directories, and feeds confirmed URLs into the scan.

**How it's exploited:** Fragments become real files — backups, web.config, source, databases, admin pages. Disclosed config, backup, and source files are flagged High.

**Fix:** Disable 8.3 generation (NtfsDisable8dot3NameCreation) and strip existing names with fsutil.`

	ModuleConfirmation = "Confirmed when the server returns distinct status codes for wildcard patterns matching existing vs non-existing 8.3 short filenames; each resolved full filename is independently re-confirmed (405-method or status-differential oracle) before being reported or queued"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"iis", "aspnet", "info-disclosure", "heavy"}
)
