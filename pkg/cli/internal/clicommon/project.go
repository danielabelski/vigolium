package clicommon

import (
	"context"
	"fmt"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

var (
	resolvedProjectUUID string
	resolveProjectOnce  sync.Once
	resolveProjectErr   error
)

// ResolveProjectUUID returns the effective project UUID, resolved once per
// process. Resolution order:
//  1. projectUUID (from --project-uuid / VIGOLIUM_PROJECT[_UUID])
//  2. projectName (DB lookup, opening the database via getDB)
//  3. ~/.vigolium/active-project file (set by `vigolium project use`)
//  4. database.DefaultProjectUUID
//
// getDB is supplied by the caller so this package needs no knowledge of the
// CLI's global flag state.
func ResolveProjectUUID(getDB func() (*database.DB, error), projectUUID, projectName string) (string, error) {
	resolveProjectOnce.Do(func() {
		switch {
		case projectUUID != "":
			resolvedProjectUUID = projectUUID
		case projectName != "":
			db, err := getDB()
			if err != nil {
				resolveProjectErr = fmt.Errorf("failed to open database for project name lookup: %w", err)
				return
			}
			repo := database.NewRepository(db)
			project, err := repo.GetProjectByName(context.Background(), projectName)
			if err != nil {
				resolveProjectErr = err
				return
			}
			resolvedProjectUUID = project.UUID
		default:
			if persisted, err := config.ReadActiveProject(); err == nil && persisted != "" {
				resolvedProjectUUID = persisted
			} else {
				resolvedProjectUUID = database.DefaultProjectUUID
			}
		}
	})
	return resolvedProjectUUID, resolveProjectErr
}

// PinProjectUUID authoritatively fixes the resolved project UUID and seals the
// resolution so every later ResolveProjectUUID call returns it, regardless of
// call ordering. This exists for --resume, which learns the run's project only
// after startup: mutating the CLI's global flags is not enough because the first
// ResolveProjectUUID call caches its result in a sync.Once. Call it during
// single-threaded startup (before any concurrent resolver use).
func PinProjectUUID(projectUUID string) {
	// Spend the Once so a subsequent ResolveProjectUUID does not overwrite the
	// pin; if it already fired, the Do is a no-op and the direct assignment below
	// still wins.
	resolveProjectOnce.Do(func() {})
	resolvedProjectUUID = projectUUID
	resolveProjectErr = nil
}
