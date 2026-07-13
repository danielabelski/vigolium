package agent

import (
	"os"
	"path/filepath"
	"time"

	"github.com/vigolium/vigolium/pkg/procutil"
	"go.uber.org/zap"
)

// CleanupOrphanedProcesses scans session directories for run.pid files and
// cleans up orphaned agent processes.
//
// A run.pid records the OWNING vigolium process's PID/PGID. An "orphan" is a run
// whose owner has DIED but which may have left agent subprocesses alive in its
// process group. So:
//
//   - If the recorded PID is still ALIVE it is NOT an orphan — it is either a
//     legitimately running concurrent vigolium instance or an unrelated process
//     that reused the PID. Either way we must not kill it. (The previous logic
//     killed alive PIDs, so starting a second run could terminate a live first
//     run or an unrelated process after PID reuse.)
//   - If the recorded PID is DEAD, the run is orphaned: reap any subprocesses
//     that outlived it in its process group, then remove the stale PID file.
//
// Returns the number of sessions cleaned up.
func CleanupOrphanedProcesses(sessionsDir string) int {
	if sessionsDir == "" {
		return 0
	}
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return 0
	}

	self := os.Getpid()
	cleaned := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pidPath := filepath.Join(sessionsDir, entry.Name(), runPIDFile)
		info := ReadRunPID(pidPath)
		if info == nil {
			continue
		}

		if info.PID == self || IsProcessAlive(info.PID) {
			// Live (or our own) session — not an orphan. Leave it running.
			zap.L().Debug("Skipping live session PID (not an orphan)",
				zap.String("session", entry.Name()),
				zap.Int("pid", info.PID))
			continue
		}

		// Owner process is dead — reap any subprocesses still alive in its group,
		// then remove the stale PID file. Killing a group whose recorded leader is
		// confirmed dead won't touch a live concurrent run.
		if info.PGID > 0 && info.PGID != self && procutil.IsProcessGroupAlive(info.PGID) {
			zap.L().Info("Reaping orphaned agent subprocess group (owner dead)",
				zap.String("session", entry.Name()),
				zap.Int("pgid", info.PGID))
			if err := killProcessGroup(info.PGID); err != nil {
				zap.L().Debug("Failed to kill orphaned process group",
					zap.Int("pgid", info.PGID), zap.Error(err))
			}
		} else {
			zap.L().Debug("Removed stale PID file (process dead)",
				zap.String("session", entry.Name()),
				zap.Int("pid", info.PID))
		}
		_ = os.Remove(pidPath)
		cleaned++
	}
	return cleaned
}

// killProcessGroup sends SIGTERM to a process group, waits up to 3 seconds,
// then escalates to SIGKILL. The platform-specific signaling lives in
// procutil (procgroup_unix.go, procgroup_windows.go).
func killProcessGroup(pgid int) error {
	if pgid <= 0 {
		return nil
	}
	if err := procutil.SignalProcessGroup(pgid, false); err != nil { // SIGTERM (graceful)
		return err
	}

	// Wait up to 3 seconds for exit.
	for i := 0; i < 6; i++ {
		time.Sleep(500 * time.Millisecond)
		if !procutil.IsProcessGroupAlive(pgid) {
			return nil
		}
	}

	// Escalate to SIGKILL.
	_ = procutil.SignalProcessGroup(pgid, true)
	return nil
}

// CleanupStaleTempDirs removes orphaned vigolium temp directories older than 24 hours.
func CleanupStaleTempDirs() {
	pattern := filepath.Join(os.TempDir(), "vigolium-swarm-ext-*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, dir := range matches {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.RemoveAll(dir); err == nil {
				zap.L().Debug("Removed stale temp dir", zap.String("path", dir))
			}
		}
	}
}
