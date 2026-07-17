import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import { z } from "zod";
import { atomicWrite, sha256OfFile, sweepStaleTempFiles } from "./util.js";
import type { AuditContext, AuditMode, AuditRecord, AuditState, PhaseStatus } from "./types.js";

const KnowledgeBaseReferenceSchema = z.object({
  source_kind: z.enum([
    "explicit-file",
    "explicit-directory",
    "raw",
    "auto-discovered",
    "resumed",
    "prior-knowledge-base-run",
  ]),
  source_label: z.string(),
  manifest_path: z.string(),
  corpus_path: z.string(),
  seed_path: z.string(),
  file_count: z.number().int().nonnegative(),
  total_bytes: z.number().int().nonnegative(),
  aggregate_sha256: z.string(),
  adopted_from_audit_id: z.string().optional(),
});

/**
 * Agent-driven (interactive harness) runs write `audit-state.json` themselves and
 * occasionally drift from our canonical status vocabulary — most commonly
 * `"completed"` for a phase the schema calls `"complete"`. Coalesce the known
 * synonyms (and any casing) on read so a merge / resume / status over an
 * agent-written file doesn't hard-fail on a cosmetic mismatch. This mirrors the
 * existing tolerance in this schema (the `mode:"full"→"deep"` migration and the
 * `branch` / `completed_at` defaulting). Re-saving the parsed state then persists
 * the canonical form, self-healing the file. Unknown tokens fall through
 * unchanged and still fail the enum loudly, so genuinely corrupt files are caught.
 */
const STATUS_SYNONYMS: Record<string, string> = {
  completed: "complete",
  done: "complete",
  success: "complete",
  succeeded: "complete",
  passed: "complete",
  "in-progress": "in_progress",
  inprogress: "in_progress",
  running: "in_progress",
  started: "in_progress",
  failure: "failed",
  errored: "failed",
  error: "failed",
  skip: "skipped",
  skip_and_continue: "skipped",
  queued: "pending",
  not_started: "pending",
  "not-started": "pending",
  cancelled: "aborted",
  canceled: "aborted",
  abort: "aborted",
};

function normalizeStatus(value: unknown): unknown {
  if (typeof value !== "string") return value;
  const key = value.trim().toLowerCase();
  return STATUS_SYNONYMS[key] ?? key;
}

const PhaseRecordSchema = z.object({
  status: z.preprocess(normalizeStatus, z.enum(["pending", "in_progress", "complete", "failed", "skipped"])),
  started_at: z.string().optional(),
  completed_at: z.string().optional(),
  failed_at: z.string().optional(),
  error: z.string().optional(),
});

const AuditRecordSchema = z.object({
  audit_id: z.string(),
  commit: z.string().nullable().default(null),
  // Older Codex handoff dispatches wrote audit-state.json without branch.
  // Defaulting keeps the handoff poller live instead of silently dropping
  // all per-phase progress on schema mismatch.
  branch: z.string().nullable().default(null),
  repository: z.string().nullable().default(null),
  history_available: z.boolean().optional(),
  source_snapshot_clean: z.boolean().optional(),
  mode: z.string(),
  model: z.string().nullable(),
  agent_sdk: z.string(),
  started_at: z.string(),
  // In-progress audits legitimately have no completion timestamp yet; tolerate
  // missing values from agent-written state and normalize to null.
  completed_at: z.string().nullable().default(null),
  status: z.preprocess(normalizeStatus, z.enum(["in_progress", "complete", "failed", "aborted"])),
  phases: z.record(z.string(), PhaseRecordSchema).default({}),
  usage: z
    .object({
      input_tokens: z.number(),
      output_tokens: z.number(),
      cost_usd: z.number(),
    })
    .optional(),
  context: z
    .object({
      focus: z.string().optional(),
      expected_behaviors: z.string().optional(),
      knowledge_base: KnowledgeBaseReferenceSchema.optional(),
    })
    .optional(),
  triggered_via: z.string().optional(),
}).passthrough();

/**
 * Schema version this build reads and writes. Bump when the on-disk shape
 * changes and add a migration step to `migrateAuditState`. A file tagged with
 * a *higher* version is rejected with a clear message rather than a cryptic
 * schema error (see `load`).
 */
export const CURRENT_AUDIT_SCHEMA_VERSION = 1;

const AuditStateSchema = z.object({
  schema_version: z.literal(1).default(1),
  audits: z.array(AuditRecordSchema),
}).passthrough();

/** Read `schema_version` without full validation, for the forward-compat guard. */
function peekSchemaVersion(json: unknown): number | null {
  if (json && typeof json === "object" && "schema_version" in json) {
    const v = (json as { schema_version?: unknown }).schema_version;
    if (typeof v === "number") return v;
  }
  return null;
}

/**
 * Bring a freshly-loaded AuditState up to the current schema, in place. This is
 * the single seam for on-disk migrations; add cases here as the schema evolves
 * rather than scattering normalization across readers.
 */
function migrateAuditState(data: AuditState): void {
  for (const audit of data.audits) {
    // Early Codex dispatch builds used `mode: "full"` for deep audits. The CLI
    // only accepts `deep`, so normalize on read to keep status/resume flows alive.
    if ((audit as { mode?: string }).mode === "full") {
      (audit as { mode: string }).mode = "deep";
    }
  }
}

const FILENAME_AUDIT = "audit-state.json";
const FILENAME_FILE = "file-state.json";

/** @see CURRENT_AUDIT_SCHEMA_VERSION — same contract, for `file-state.json`. */
export const CURRENT_FILE_SCHEMA_VERSION = 2 as const;

const FileStateSchema = z.object({
  schema_version: z.literal(2).default(2),
  files: z.record(
    z.string(),
    z.object({
      sha256: z.string(),
      /** Most recent audits to stamp this file, oldest first, capped at 5. */
      last_audits: z.array(z.string()),
      /**
       * Phases that ran in the audit that last stamped this hash — NOT the
       * phases that read this file. No producer collects per-file attribution,
       * so every file in one audit carries the same list.
       */
      audit_phases: z.array(z.string()),
    }),
  ),
});

export type FileState = z.infer<typeof FileStateSchema>;

/**
 * v1 called this field `last_phases` and capped it at five entries, which read
 * as per-file attribution but never was: both producers stamped the audit's
 * whole phase set onto every file, and the cap silently kept an arbitrary
 * subset (the Python stamper sorted phase IDs as strings, so a 12-phase deep
 * audit persisted D5-D9 and dropped D1-D4). v2 renames the field to what it
 * always meant and drops the cap — phase sets are bounded by the mode's YAML
 * graph, so they can't grow without limit.
 *
 * Carried v1 values stay truncated; the next audit overwrites them wholesale.
 * Migrating rather than invalidating keeps the sha256 baseline, which is the
 * half that actually drives incremental scope.
 */
function migrateFileState(json: unknown): unknown {
  if (!json || typeof json !== "object") return json;
  const root = json as { schema_version?: unknown; files?: unknown };
  if (root.schema_version !== 1) return json;
  if (root.files && typeof root.files === "object") {
    for (const entry of Object.values(root.files as Record<string, unknown>)) {
      if (!entry || typeof entry !== "object") continue;
      const rec = entry as { last_phases?: unknown; audit_phases?: unknown };
      if (rec.audit_phases === undefined && rec.last_phases !== undefined) {
        rec.audit_phases = rec.last_phases;
      }
      delete rec.last_phases;
    }
  }
  root.schema_version = CURRENT_FILE_SCHEMA_VERSION;
  return json;
}

export class StateStore {
  /**
   * Tail of an in-flight write chain. Every read-modify-write awaits this and
   * then assigns its own promise, serializing concurrent updates so two
   * phases running in parallel don't lose each other's writes.
   */
  private writeChain: Promise<unknown> = Promise.resolve();

  /** One-shot cleanup of staging files orphaned by a crash mid-write. */
  private sweepOnce: Promise<void> | null = null;

  constructor(private readonly resultsDir: string) {}

  /** Sweep orphaned `atomicWrite` staging files once, before the first write. */
  private sweep(): Promise<void> {
    if (!this.sweepOnce) this.sweepOnce = sweepStaleTempFiles(this.resultsDir);
    return this.sweepOnce;
  }

  private auditPath(): string {
    return join(this.resultsDir, FILENAME_AUDIT);
  }
  private filePath(): string {
    return join(this.resultsDir, FILENAME_FILE);
  }

  /** Serialize an async section against any other in-flight write on this store. */
  private async withWriteLock<T>(fn: () => Promise<T>): Promise<T> {
    const prev = this.writeChain;
    let release: (v: unknown) => void = () => {};
    this.writeChain = new Promise((r) => { release = r; });
    try {
      await prev.catch(() => {});
      await this.sweep();
      return await fn();
    } finally {
      release(undefined);
    }
  }

  async load(): Promise<AuditState> {
    if (!existsSync(this.auditPath())) {
      return { schema_version: 1, audits: [] };
    }
    const raw = await readFile(this.auditPath(), "utf8");
    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch (err) {
      throw new Error(`audit-state.json: invalid JSON: ${(err as Error).message}`);
    }
    // Forward-compat: a file written by a newer build may carry a structure
    // this build can't safely interpret. Detect that explicitly so users get an
    // actionable "upgrade" message instead of a cryptic schema error.
    const version = peekSchemaVersion(json);
    if (version !== null && version > CURRENT_AUDIT_SCHEMA_VERSION) {
      throw new Error(
        `audit-state.json: schema_version ${version} is newer than this build supports (${CURRENT_AUDIT_SCHEMA_VERSION}); upgrade vigolium-audit`,
      );
    }
    const parsed = AuditStateSchema.safeParse(json);
    if (!parsed.success) {
      throw new Error(`audit-state.json: schema mismatch: ${parsed.error.message}`);
    }
    const data = parsed.data as AuditState;
    migrateAuditState(data);
    return data;
  }

  async save(state: AuditState): Promise<void> {
    await atomicWrite(this.auditPath(), JSON.stringify(state, null, 2) + "\n");
  }

  async appendAudit(record: AuditRecord): Promise<AuditState> {
    return this.withWriteLock(async () => {
      const state = await this.load();
      state.audits.push(record);
      await this.save(state);
      return state;
    });
  }

  async updatePhase(
    auditId: string,
    phaseId: string,
    update: Partial<{ status: PhaseStatus; started_at: string; completed_at: string; failed_at: string; error: string }>,
  ): Promise<void> {
    return this.withWriteLock(async () => {
      const state = await this.load();
      const audit = state.audits.find((a) => a.audit_id === auditId);
      if (!audit) throw new Error(`audit ${auditId} not found in state`);
      const existing = audit.phases[phaseId] ?? { status: "pending" as PhaseStatus };
      audit.phases[phaseId] = { ...existing, ...update };
      await this.save(state);
    });
  }

  async updateAudit(
    auditId: string,
    update: Partial<Pick<
      AuditRecord,
      "status" | "completed_at" | "model" | "usage" | "source_snapshot_clean"
    >>,
  ): Promise<void> {
    return this.withWriteLock(async () => {
      const state = await this.load();
      const audit = state.audits.find((a) => a.audit_id === auditId);
      if (!audit) throw new Error(`audit ${auditId} not found in state`);
      Object.assign(audit, update);
      await this.save(state);
    });
  }

  async latestAudit(mode?: AuditMode | "any"): Promise<AuditRecord | null> {
    const state = await this.load();
    const candidates = mode && mode !== "any" ? state.audits.filter((a) => a.mode === mode) : state.audits;
    if (candidates.length === 0) return null;
    return candidates[candidates.length - 1] ?? null;
  }

  async loadFileState(): Promise<FileState> {
    if (!existsSync(this.filePath())) {
      return { schema_version: CURRENT_FILE_SCHEMA_VERSION, files: {} };
    }
    const raw = await readFile(this.filePath(), "utf8");
    let json: unknown;
    try {
      json = JSON.parse(raw);
    } catch (err) {
      throw new Error(`file-state.json: invalid JSON: ${(err as Error).message}`);
    }
    const version = peekSchemaVersion(json);
    if (version !== null && version > CURRENT_FILE_SCHEMA_VERSION) {
      throw new Error(
        `file-state.json: schema_version ${version} is newer than this build supports (${CURRENT_FILE_SCHEMA_VERSION}); upgrade vigolium-audit`,
      );
    }
    const parsed = FileStateSchema.safeParse(migrateFileState(json));
    if (!parsed.success) throw new Error(`file-state.json: schema mismatch: ${parsed.error.message}`);
    return parsed.data;
  }

  async saveFileState(state: FileState): Promise<void> {
    await atomicWrite(this.filePath(), JSON.stringify(state, null, 2) + "\n");
  }

  /**
   * Hash each file in `files` (relative to targetDir) and merge into
   * file-state.json. This is the only producer of the file — the audit content
   * must not write it directly, or the index picks up paths git doesn't track.
   *
   * `last_audits` accumulates across runs (capped at 5; audits are unbounded).
   * `audit_phases` is overwritten with this audit's completed phases: it
   * describes the stamping audit, not the file, so merging prior values would
   * only blur which run the hash belongs to.
   */
  async recordFileSnapshot(args: {
    targetDir: string;
    files: string[];
    auditId: string;
    completedPhaseIds: string[];
    /**
     * Drop entries absent from `files`, so deletions leave the index. Only
     * correct when `files` is the complete set for the target — a partial list
     * would silently discard the rest of the baseline.
     */
    prune?: boolean;
  }): Promise<void> {
    return this.withWriteLock(async () => {
      const existing = await this.loadFileState().catch(() => ({
        schema_version: CURRENT_FILE_SCHEMA_VERSION,
        files: {} as FileState["files"],
      }));
      // Parallelize the hashing — IO-bound and the file count can run into
      // the tens of thousands. Returns null entries for unreadable files.
      const hashes = await Promise.all(
        args.files.map(async (rel) => ({ rel, sha: await sha256OfFile(join(args.targetDir, rel)) })),
      );
      const next: FileState["files"] = args.prune ? {} : existing.files;
      for (const { rel, sha } of hashes) {
        if (sha === null) continue;
        const prev = existing.files[rel];
        next[rel] = {
          sha256: sha,
          last_audits: appendUnique(prev?.last_audits ?? [], args.auditId, 5),
          audit_phases: [...args.completedPhaseIds],
        };
      }
      existing.files = next;
      await this.saveFileState(existing);
    });
  }
}

function appendUnique(list: string[], item: string, cap: number): string[] {
  const filtered = list.filter((x) => x !== item);
  filtered.push(item);
  return filtered.slice(-cap);
}

export function buildAuditId(now: Date = new Date()): string {
  return now.toISOString();
}

/**
 * Pick the latest audit for `mode` that didn't reach `complete` — the single
 * resume-resolution rule shared by the Orchestrator and the handoff drivers.
 * `in_progress` covers process-killed-mid-phase; `failed`/`aborted` cover
 * orderly terminal states (cost cap, strict failure, SIGINT). Each is
 * resumable: completed phases are skipped, pending re-runs, stale in_progress
 * phases get quarantined in phase prep. Returns null when nothing matches.
 */
export function findResumableAudit(audits: AuditRecord[], mode: AuditMode): AuditRecord | null {
  return (
    [...audits]
      .reverse()
      .find(
        (a) => a.mode === mode && isResumableAudit(a),
      ) ?? null
  );
}

/** Resolve the exact resumable record selected by a higher-level router. */
export function findResumableAuditById(
  audits: AuditRecord[],
  auditId: string,
  mode?: AuditMode,
): AuditRecord | null {
  return audits.find(
    (audit) =>
      audit.audit_id === auditId &&
      (mode === undefined || audit.mode === mode) &&
      isResumableAudit(audit),
  ) ?? null;
}

function isResumableAudit(audit: AuditRecord): boolean {
  return audit.status === "in_progress" || audit.status === "failed" || audit.status === "aborted";
}

export function newAuditRecord(opts: {
  audit_id: string;
  mode: AuditMode;
  agent_sdk: string;
  model: string | null;
  commit: string | null;
  branch: string | null;
  repository: string | null;
  historyAvailable: boolean;
  sourceSnapshotClean?: boolean;
  phaseIds: string[];
  startedAt?: string;
  context?: AuditContext;
  triggeredVia?: string;
}): AuditRecord {
  const phases: Record<string, { status: PhaseStatus }> = {};
  for (const id of opts.phaseIds) phases[id] = { status: "pending" };
  return {
    audit_id: opts.audit_id,
    commit: opts.commit,
    branch: opts.branch,
    repository: opts.repository,
    history_available: opts.historyAvailable,
    ...(opts.sourceSnapshotClean !== undefined
      ? { source_snapshot_clean: opts.sourceSnapshotClean }
      : {}),
    mode: opts.mode,
    model: opts.model,
    agent_sdk: opts.agent_sdk,
    started_at: opts.startedAt ?? new Date().toISOString(),
    completed_at: null,
    status: "in_progress",
    phases,
    ...(opts.context !== undefined && hasContextContent(opts.context)
      ? { context: opts.context }
      : {}),
    ...(opts.triggeredVia !== undefined && opts.triggeredVia.length > 0
      ? { triggered_via: opts.triggeredVia }
      : {}),
  };
}

function hasContextContent(c: AuditContext): boolean {
  return (
    (typeof c.focus === "string" && c.focus.length > 0) ||
    (typeof c.expected_behaviors === "string" && c.expected_behaviors.length > 0) ||
    c.knowledge_base !== undefined
  );
}
