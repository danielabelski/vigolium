package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// TestAgentEndpoints_ProjectScoping verifies the agent run point endpoints and
// the status list refuse to expose or cancel a run owned by another project.
// Routes are registered without the project middleware, so getProjectUUID
// resolves to DefaultProjectUUID; a run seeded under a different project must be
// invisible (404) and absent from the list (CR-01).
func TestAgentEndpoints_ProjectScoping(t *testing.T) {
	const otherProject = "22222222-2222-2222-2222-222222222222"

	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)

	otherRun := "run-" + randSuffix()
	if err := repo.CreateAgenticScan(context.Background(), &database.AgenticScan{
		UUID: otherRun, ProjectUUID: otherProject, Mode: "autopilot", Status: "completed",
	}); err != nil {
		t.Fatalf("CreateAgenticScan(other): %v", err)
	}
	sameRun := "run-" + randSuffix()
	if err := repo.CreateAgenticScan(context.Background(), &database.AgenticScan{
		UUID: sameRun, ProjectUUID: database.DefaultProjectUUID, Mode: "autopilot", Status: "completed",
	}); err != nil {
		t.Fatalf("CreateAgenticScan(same): %v", err)
	}

	app := fiber.New()
	app.Get("/api/agent/status/list", h.HandleAgenticScanList)
	app.Get("/api/agent/status/:id", h.HandleAgenticScanStatus)
	app.Get("/api/agent/sessions/:id", h.HandleAgentSessionDetail)
	app.Post("/api/agent/scans/:uuid/cancel", h.HandleAgentCancel)

	// Cross-project point endpoints → 404.
	if status, body := doReq(t, app, http.MethodGet, "/api/agent/status/"+otherRun, "", nil); status != http.StatusNotFound {
		t.Errorf("status/:id cross-project = %d, want 404; body %s", status, body)
	}
	if status, body := doReq(t, app, http.MethodGet, "/api/agent/sessions/"+otherRun, "", nil); status != http.StatusNotFound {
		t.Errorf("sessions/:id cross-project = %d, want 404; body %s", status, body)
	}

	// Same-project run IS reachable, proving the 404s are scoping not a broken route.
	if status, body := doReq(t, app, http.MethodGet, "/api/agent/status/"+sameRun, "", nil); status != http.StatusOK {
		t.Errorf("same-project status = %d, want 200; body %s", status, body)
	}

	// The list includes the same-project run but never the other project's.
	status, body := doReq(t, app, http.MethodGet, "/api/agent/status/list", "", nil)
	if status != http.StatusOK {
		t.Fatalf("status/list = %d, want 200; body %s", status, body)
	}
	if !strings.Contains(string(body), sameRun) {
		t.Errorf("status/list should include the same-project run: %s", body)
	}
	if strings.Contains(string(body), otherRun) {
		t.Errorf("status/list leaked another project's run: %s", body)
	}

	// A running run owned by another project must not be cancellable.
	cancelled := false
	h.agentMu.Lock()
	h.agenticScanStatus["x-run"] = &AgenticScanStatusResponse{
		AgenticScanUUID: "x-run", ProjectUUID: otherProject, Status: "running",
	}
	h.agentMu.Unlock()
	h.registerRunCancel("x-run", func() { cancelled = true })
	if status, _ := doReq(t, app, http.MethodPost, "/api/agent/scans/x-run/cancel", "", nil); status != http.StatusNotFound {
		t.Errorf("cross-project cancel = %d, want 404", status)
	}
	if cancelled {
		t.Error("cross-project cancel must not invoke the run's cancel func")
	}
}
