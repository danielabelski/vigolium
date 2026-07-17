import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { newAuditRecord, StateStore } from "../../src/engine/state.js";
import {
  knowledgeBaseReference,
  resolveKnowledgeBaseInput,
  stageKnowledgeBaseInput,
} from "../../src/engine/knowledge-base.js";

const CLI_ENTRY = resolve(import.meta.dir, "../../src/index.ts");
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  tempDirs.length = 0;
});

function target(): string {
  const dir = mkdtempSync(join(tmpdir(), "vigolium-kb-cli-"));
  tempDirs.push(dir);
  return dir;
}

async function run(
  args: string[],
  extraEnv: Record<string, string> = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["bun", "run", CLI_ENTRY, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    env: {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      ...extraEnv,
    },
  });
  const [code, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { code, stdout, stderr };
}

describe("knowledge-base CLI dry run", () => {
  test("auto-discovery enables KB0 and exposes only safe metadata", async () => {
    const root = target();
    const docs = join(root, "knowledge-base");
    mkdirSync(docs);
    writeFileSync(join(docs, "auth.md"), "# Auth\n\nSuper secret architecture sentence.\n");

    const result = await run([
      "run",
      "--mode",
      "lite",
      "--target",
      root,
      "--dry-run",
      "--json",
    ]);
    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout);
    expect(payload.knowledgeBase.sourceKind).toBe("auto-discovered");
    expect(payload.knowledgeBase.fileCount).toBe(1);
    expect(payload.plans[0].phases.find((phase: { id: string }) => phase.id === "KB0").skipped)
      .toBe(false);
    expect(result.stdout).not.toContain("Super secret architecture sentence");
  });

  test("KB0 is skipped when no source is resolved", async () => {
    const root = target();
    const result = await run([
      "run",
      "--mode",
      "balanced",
      "--target",
      root,
      "--dry-run",
      "--json",
    ]);
    expect(result.code).toBe(0);
    const payload = JSON.parse(result.stdout);
    expect(payload.knowledgeBase).toBeNull();
    const kb0 = payload.plans[0].phases.find((phase: { id: string }) => phase.id === "KB0");
    expect(kb0.skipped).toBe(true);
    expect(kb0.skipReason).toContain("no knowledge-base");
  });

  test("rejects knowledge-base flags for a mode that cannot consume them", async () => {
    const root = target();
    const result = await run([
      "run",
      "--mode",
      "confirm",
      "--target",
      root,
      "--knowledge-base-raw",
      "# Auth",
      "--dry-run",
      "--json",
    ]);
    expect(result.code).toBe(2);
    expect(result.stdout).toContain("only supported by lite, balanced, deep, and knowledge-base modes");
  });

  test("rejects knowledge-base input when refresh resolves to revisit", async () => {
    const root = target();
    const results = join(root, "vigolium-results");
    mkdirSync(join(results, "attack-surface"), { recursive: true });
    mkdirSync(join(results, "findings", "H-001-example"), { recursive: true });
    writeFileSync(join(results, "attack-surface", "knowledge-base-report.md"), "# KB\n");
    const store = new StateStore(results);
    await store.appendAudit(newAuditRecord({
      audit_id: "complete-deep",
      mode: "deep",
      agent_sdk: "test",
      model: null,
      commit: null,
      branch: null,
      repository: null,
      historyAvailable: false,
      phaseIds: [],
    }));
    await store.updateAudit("complete-deep", {
      status: "complete",
      completed_at: new Date().toISOString(),
    });

    const result = await run([
      "run",
      "--mode",
      "refresh",
      "--target",
      root,
      "--knowledge-base-raw",
      "# Auth",
      "--dry-run",
      "--json",
    ]);
    expect(result.code).toBe(2);
    expect(result.stdout).toContain("refresh routed to revisit");
  });

  test("automatic refresh resume reloads and validates the original knowledge-base flag", async () => {
    const root = target();
    const source = join(root, "auth.md");
    writeFileSync(source, "# Auth\n\nOriginal flow.\n");
    const input = await resolveKnowledgeBaseInput({ targetDir: root, path: source });
    const results = join(root, "vigolium-results");
    await stageKnowledgeBaseInput(results, input!);
    await new StateStore(results).appendAudit(newAuditRecord({
      audit_id: "refresh-deep-in-progress",
      mode: "deep",
      agent_sdk: "test",
      model: null,
      commit: null,
      branch: null,
      repository: null,
      historyAvailable: false,
      phaseIds: ["KB0", "D1"],
      context: { knowledge_base: knowledgeBaseReference(input!) },
      triggeredVia: "refresh",
    }));
    writeFileSync(source, "# Auth\n\nChanged flow.\n");

    const home = join(root, "test-home");
    mkdirSync(home, { recursive: true });
    const result = await run([
      "run",
      "--mode",
      "refresh",
      "--target",
      root,
      "--agent",
      "codex",
      "--transport",
      "cli",
      "--knowledge-base",
      source,
      "--no-git",
      "--json",
    ], {
      HOME: home,
      VIGOLIUM_AUDIT_CODEX_PATH: "/usr/bin/true",
      VIGOLIUM_AUDIT_HARNESS_CODEX_DIR: join(home, ".codex", "agents"),
      VIGOLIUM_AUDIT_HARNESS_CODEX_SKILLS_DIR: join(home, ".codex", "skills"),
      VIGOLIUM_AUDIT_HARNESS_CODEX_AGENTS_MD: join(home, ".codex", "AGENTS.md"),
      VIGOLIUM_AUDIT_RUNTIME_SKILLS_DIR: join(home, ".config", "vigolium-audit", "runtime-skills"),
    });

    expect(result.code).toBe(1);
    expect(result.stdout).toContain("knowledge-base input changed since this audit started");
  });

  test("resume binds the staged corpus to the exact audit selected by status priority", async () => {
    const root = target();
    const results = join(root, "vigolium-results");
    const auditA = await resolveKnowledgeBaseInput({
      targetDir: root,
      raw: "# Audit A\n\nOriginal corpus.\n",
    });
    const auditB = await resolveKnowledgeBaseInput({
      targetDir: root,
      raw: "# Audit B\n\nReplacement corpus.\n",
    });
    const store = new StateStore(results);
    await store.appendAudit(newAuditRecord({
      audit_id: "older-in-progress-A",
      mode: "deep",
      agent_sdk: "test",
      model: null,
      commit: null,
      branch: null,
      repository: null,
      historyAvailable: false,
      phaseIds: ["KB0", "D1"],
      context: { knowledge_base: knowledgeBaseReference(auditA!) },
    }));
    await store.appendAudit(newAuditRecord({
      audit_id: "newer-failed-B",
      mode: "deep",
      agent_sdk: "test",
      model: null,
      commit: null,
      branch: null,
      repository: null,
      historyAvailable: false,
      phaseIds: ["KB0", "D1"],
      context: { knowledge_base: knowledgeBaseReference(auditB!) },
    }));
    await store.updateAudit("newer-failed-B", {
      status: "failed",
      completed_at: new Date().toISOString(),
    });
    await stageKnowledgeBaseInput(results, auditB!);

    const result = await run(["resume", root, "--json"]);

    expect(result.code).toBe(2);
    expect(result.stdout).toContain("cannot resume audit older-in-progress-A");
    expect(result.stdout).toContain("does not match the corpus recorded");
  });
});
