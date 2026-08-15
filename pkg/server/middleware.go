package server

import (
	"database/sql"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

const projectUUIDLocalsKey = "project_uuid"

// ProjectUUIDMiddleware extracts the project UUID from the X-Project-UUID
// request header and stores it in Fiber locals. Falls back to DefaultProjectUUID
// when the header is empty.
//
// When repo is non-nil and the supplied UUID does not exist in the database,
// the middleware lazily creates a stub project row so callers (including UIs
// after a scanner DB reset) can keep working with the UUID stored client-side.
// Auto-creation is skipped for public/utility endpoints and for the default
// project UUID, which is seeded separately.
func ProjectUUIDMiddleware(repo *database.Repository) fiber.Handler {
	return func(c fiber.Ctx) error {
		projectUUID := c.Get("X-Project-UUID")
		if projectUUID == "" {
			projectUUID = database.DefaultProjectUUID
		}
		c.Locals(projectUUIDLocalsKey, projectUUID)

		if repo != nil && projectUUID != database.DefaultProjectUUID && !isPublicProjectPath(c.Path()) {
			ensureProjectExists(c, repo, projectUUID)
		}

		return c.Next()
	}
}

// isPublicProjectPath returns true for endpoints that should never trigger
// project auto-creation (health checks, swagger, static UI, etc.).
func isPublicProjectPath(path string) bool {
	if path == "/" || path == "/health" || path == "/ready" || path == "/server-info" || path == "/metrics" {
		return true
	}
	return strings.HasPrefix(path, "/swagger")
}

// ensureProjectExists looks up the project by UUID and inserts a stub row if
// it is missing. Errors are logged but never block the request — the next
// middleware/handler will surface a downstream error if the row truly
// can't be reached.
func ensureProjectExists(c fiber.Ctx, repo *database.Repository, projectUUID string) {
	if _, err := repo.GetProjectByUUID(c.Context(), projectUUID); err == nil {
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		// Real DB error — log and bail out without trying to write.
		zap.L().Debug("project lookup failed; skipping auto-create",
			zap.String("project_uuid", projectUUID),
			zap.Error(err))
		return
	}

	name := "auto-" + projectUUID
	if len(projectUUID) >= 8 {
		name = "auto-" + projectUUID[:8]
	}
	now := time.Now().UTC()
	stub := &database.Project{
		UUID:        projectUUID,
		Name:        name,
		Description: "Auto-created on first use",
		OwnerUUID:   database.DefaultUserUUID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := repo.CreateProject(c.Context(), stub); err != nil {
		// Likely a race with a concurrent insert — verify the row landed.
		if _, getErr := repo.GetProjectByUUID(c.Context(), projectUUID); getErr == nil {
			return
		}
		zap.L().Warn("failed to auto-create project",
			zap.String("project_uuid", projectUUID),
			zap.Error(err))
		return
	}
	zap.L().Info("auto-created project on first use",
		zap.String("project_uuid", projectUUID),
		zap.String("name", name))
}

// getProjectUUID retrieves the project UUID from Fiber context locals.
func getProjectUUID(c fiber.Ctx) string {
	if v, ok := c.Locals(projectUUIDLocalsKey).(string); ok && v != "" {
		return v
	}
	return database.DefaultProjectUUID
}

// inRequestProject reports whether a loaded row (records, findings, OAST
// interactions, scans) belongs to the request's active project (X-Project-UUID,
// or the default project when the header is absent). Point endpoints that fetch
// by a global id/uuid use this to enforce project-selection semantics — the
// docs promise the header scopes all operations — so an operator scoped to one
// engagement can't read, mutate, or delete another's data via a raw id. Callers
// surface a mismatch as 404 (not 403) so cross-project existence isn't leaked.
func inRequestProject(c fiber.Ctx, rowProjectUUID string) bool {
	return rowProjectUUID == getProjectUUID(c)
}

const authUserLocalsKey = "auth_user"

// BearerAuth returns fiber middleware that validates Bearer tokens and resolves user identity.
// Checks the UserStore first (file-based users), then falls back to legacy API keys (admin role).
// Skips authentication for public endpoints: /, /health, /ready, /swagger/*, /metrics.
func BearerAuth(validKeys []string, store *UserStore) fiber.Handler {
	return func(c fiber.Ctx) error {
		path := c.Path()
		// Skip auth for public endpoints
		if path == "/" || path == "/health" || path == "/ready" || path == "/metrics" || strings.HasPrefix(path, "/swagger") {
			return c.Next()
		}

		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error: ErrMissingAuthHeader.Error(),
				Code:  fiber.StatusUnauthorized,
			})
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader || token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error: ErrInvalidAuthToken.Error(),
				Code:  fiber.StatusUnauthorized,
			})
		}

		// 1. Try file-based user store first
		if user := store.Lookup(token); user != nil {
			c.Locals(authUserLocalsKey, user)
			return c.Next()
		}

		// 2. Fall back to legacy API key → admin
		if slices.Contains(validKeys, token) {
			c.Locals(authUserLocalsKey, &ResolvedUser{
				UUID: database.DefaultUserUUID,
				Name: "vigolium-admin",
				Role: RoleAdmin,
			})
			return c.Next()
		}

		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error: ErrInvalidAuthToken.Error(),
			Code:  fiber.StatusUnauthorized,
		})
	}
}

// getAuthUser retrieves the resolved user from Fiber context locals.
func getAuthUser(c fiber.Ctx) *ResolvedUser {
	if v, ok := c.Locals(authUserLocalsKey).(*ResolvedUser); ok {
		return v
	}
	return nil
}

// RoleGuard returns middleware that rejects requests from users whose role
// is not in the allowed set. Must be applied after BearerAuth.
// When no auth user is present (--no-auth mode), requests are allowed through.
func RoleGuard(allowed ...string) fiber.Handler {
	set := make(map[string]bool, len(allowed))
	for _, r := range allowed {
		set[r] = true
	}
	return func(c fiber.Ctx) error {
		user := getAuthUser(c)
		if user == nil {
			// No user means auth was skipped (--no-auth) → allow
			return c.Next()
		}
		if !set[user.Role] {
			return c.Status(fiber.StatusForbidden).JSON(ErrorResponse{
				Error: ErrForbidden.Error(),
				Code:  fiber.StatusForbidden,
			})
		}
		return c.Next()
	}
}

// DebugRequestMiddleware logs the raw request body, URL/query parameters,
// and headers for every incoming request when --debug is enabled.
//
// Sensitive headers and BYOK body fields are scrubbed before the line is
// emitted — see redact.go for the precise lists. JSON-shaped bodies are
// parsed and re-serialized; non-JSON or malformed bodies are summarized
// rather than logged verbatim so a binary upload doesn't tank the log.
func DebugRequestMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		fields := []zap.Field{
			zap.String("method", c.Method()),
			zap.String("path", c.Path()),
		}

		// Query parameters — scoped scrubbing isn't worth it here because
		// the same secret field names aren't passed as query strings on any
		// agent endpoint. If that changes, extend redact.go to also walk a
		// url.Values map.
		if raw := string(c.Request().URI().QueryString()); raw != "" {
			fields = append(fields, zap.String("query", raw))
		}

		// Headers
		fields = append(fields, zap.Any("headers", redactSensitiveHeaders(c.GetReqHeaders())))

		// Body (for POST/PUT/PATCH). Never on the large-upload routes: c.Body()
		// on a streamed upload drains the whole object into memory, so with
		// --debug on, logging alone would materialize a half-gigabyte tarball
		// that the handler was carefully staging to disk. Log its shape instead.
		if bodyLimitExemptPaths[c.Path()] {
			fields = append(fields,
				zap.String("body", "<not read: upload route>"),
				zap.Int("declared_content_length", c.Request().Header.ContentLength()))
		} else if body := c.Body(); len(body) > 0 {
			if scrubbed := redactJSONBody(body); len(scrubbed) > 0 {
				fields = append(fields, zap.ByteString("body", scrubbed))
			}
		}

		zap.L().Debug("Incoming request", fields...)

		return c.Next()
	}
}

const defaultBodyLimit = 4 << 20 // 4 MB — default for non-upload routes

// maxOversizeDrainBytes is how much of a rejected body is discarded so the
// sender can finish and read the 413 instead of taking a connection reset. It
// is a courtesy budget, not a limit: nothing is retained, but neither is the
// server willing to spend unbounded socket time reading bytes it has already
// refused.
const maxOversizeDrainBytes = 8 << 20 // 8 MB

// bodyLimitExemptPaths are routes that accept large uploads (archive bundles,
// source-code tarballs) and must skip the 4 MB cap. The matching is exact —
// every entry covers a single POST endpoint.
var bodyLimitExemptPaths = map[string]bool{
	"/api/import":                true,
	"/api/storage/upload-source": true,
}

// DefaultBodyLimitMiddleware rejects request bodies larger than defaultBodyLimit
// for routes that aren't in bodyLimitExemptPaths.
//
// With StreamRequestBody enabled (see fiber.Config) the declared-Content-Length
// check rejects an oversized body before it is read into memory, so a normal
// JSON route no longer buffers up to the framework's 512 MB ceiling just to
// bounce it. A chunked or otherwise undeclared body has no length to check, and
// there the naive `len(c.Body()) > limit` is the problem rather than the fix:
// c.Body() drains the stream first and asks afterwards, and the only ceiling on
// that drain is the framework BodyLimit — so a sender who omits Content-Length
// gets to grow the server's heap by 512 MB per request on a route whose limit is
// 4 MB, and a handful of concurrent senders can exhaust memory on requests that
// were always going to be rejected.
//
// So the undeclared case is read explicitly, through a reader capped one byte
// past the limit: at most limit+1 bytes are ever allocated, and crossing the
// threshold is detectable without having consumed what follows.
func DefaultBodyLimitMiddleware() fiber.Handler {
	tooLarge := func(c fiber.Ctx) error {
		if req := c.Request(); req.IsBodyStream() {
			_, _ = io.Copy(io.Discard, io.LimitReader(req.BodyStream(), maxOversizeDrainBytes))
		}
		// Whatever is left unread would be parsed as the next request on this
		// connection, so it cannot be reused.
		c.Response().Header.SetConnectionClose()
		return c.Status(fiber.StatusRequestEntityTooLarge).JSON(ErrorResponse{
			Error: "request body exceeds 4 MB limit",
		})
	}
	return func(c fiber.Ctx) error {
		if bodyLimitExemptPaths[c.Path()] {
			return c.Next()
		}

		req := c.Request()
		cl := req.Header.ContentLength()
		if cl > defaultBodyLimit {
			return tooLarge(c)
		}
		if cl < 0 && req.IsBodyStream() {
			// Undeclared length (chunked or identity). Read at most limit+1.
			// Deliberately not pre-sized: the cap is 4 MB and most requests are
			// a few hundred bytes, so ReadAll's growth beats allocating the
			// ceiling every time.
			body, err := io.ReadAll(io.LimitReader(req.BodyStream(), defaultBodyLimit+1))
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
					Error: "failed to read request body: " + err.Error(),
				})
			}
			if len(body) > defaultBodyLimit {
				return tooLarge(c)
			}
			// Hand the bytes back as an ordinary in-memory body. SetBodyRaw
			// adopts the slice rather than copying it into the pooled body
			// buffer (SetBody would), which is safe because we own it and
			// nothing else aliases it; it also closes and releases the stream,
			// correct here since we have read everything it could produce.
			req.SetBodyRaw(body)
		}
		if len(c.Body()) > defaultBodyLimit {
			return tooLarge(c)
		}
		return c.Next()
	}
}

// AuthorHeaderMiddleware stamps the `X-Author:` response header, the companion
// to the `Server:` banner. The value comes from ServerConfig.Author (wired from
// pkg/cli.Author) rather than a literal here — pkg/server cannot import pkg/cli
// without an import cycle, and a second copy of the name would drift.
// registerRoutes skips this middleware entirely when the author is unset, so an
// empty header is never written.
func AuthorHeaderMiddleware(author string) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Set("X-Author", author)
		return c.Next()
	}
}

// SecurityHeadersMiddleware adds security headers to all responses.
func SecurityHeadersMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-XSS-Protection", "1; mode=block")
		return c.Next()
	}
}
