import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { createHash } from "crypto";
import { StateStore } from "../../src/engine/state.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs) rmSync(d, { recursive: true, force: true });
  tempDirs.length = 0;
});

function makeDir(): string {
  const d = mkdtempSync(join(tmpdir(), "vigolium-audit-filestate-"));
  tempDirs.push(d);
  return d;
}

describe("StateStore.recordFileSnapshot", () => {
  test("hashes tracked files and persists attribution", async () => {
    const target = makeDir();
    mkdirSync(join(target, "src"), { recursive: true });
    writeFileSync(join(target, "src", "a.ts"), "alpha\n");
    writeFileSync(join(target, "src", "b.ts"), "beta\n");

    const store = new StateStore(join(target, "vigolium-results"));
    await store.recordFileSnapshot({
      targetDir: target,
      files: ["src/a.ts", "src/b.ts"],
      auditId: "audit-1",
      completedPhaseIds: ["L1", "L2"],
    });

    const state = await store.loadFileState();
    const expectA = createHash("sha256").update("alpha\n").digest("hex");
    expect(state.files["src/a.ts"]!.sha256).toBe(expectA);
    expect(state.files["src/a.ts"]!.last_audits).toEqual(["audit-1"]);
    expect(state.files["src/a.ts"]!.audit_phases).toEqual(["L1", "L2"]);
  });

  test("accumulates audits (capped at 5) but overwrites phases with the current audit", async () => {
    const target = makeDir();
    writeFileSync(join(target, "a.ts"), "x");
    const store = new StateStore(join(target, "vigolium-results"));

    for (let i = 1; i <= 7; i++) {
      await store.recordFileSnapshot({
        targetDir: target,
        files: ["a.ts"],
        auditId: `audit-${i}`,
        completedPhaseIds: [`P${i}`],
      });
    }
    const state = await store.loadFileState();
    expect(state.files["a.ts"]!.last_audits.length).toBe(5);
    expect(state.files["a.ts"]!.last_audits).toContain("audit-7");
    expect(state.files["a.ts"]!.last_audits).not.toContain("audit-1");
    // audit_phases describes the stamping audit, so it reflects only the last.
    expect(state.files["a.ts"]!.audit_phases).toEqual(["P7"]);
  });

  test("retains every phase of a 12-phase deep audit (v1 capped this at 5)", async () => {
    const target = makeDir();
    writeFileSync(join(target, "a.ts"), "x");
    const store = new StateStore(join(target, "vigolium-results"));
    const deepPhases = Array.from({ length: 12 }, (_, i) => `D${i + 1}`);

    await store.recordFileSnapshot({
      targetDir: target,
      files: ["a.ts"],
      auditId: "audit-1",
      completedPhaseIds: deepPhases,
    });
    const state = await store.loadFileState();
    expect(state.files["a.ts"]!.audit_phases).toEqual(deepPhases);
  });

  test("prune drops entries for files deleted since the last audit", async () => {
    const target = makeDir();
    writeFileSync(join(target, "keep.ts"), "k");
    writeFileSync(join(target, "gone.ts"), "g");
    const store = new StateStore(join(target, "vigolium-results"));

    await store.recordFileSnapshot({
      targetDir: target,
      files: ["keep.ts", "gone.ts"],
      auditId: "audit-1",
      completedPhaseIds: ["L1"],
      prune: true,
    });
    expect((await store.loadFileState()).files["gone.ts"]).toBeDefined();

    rmSync(join(target, "gone.ts"));
    await store.recordFileSnapshot({
      targetDir: target,
      files: ["keep.ts"],
      auditId: "audit-2",
      completedPhaseIds: ["L1"],
      prune: true,
    });
    const after = await store.loadFileState();
    expect(after.files["keep.ts"]).toBeDefined();
    expect(after.files["gone.ts"]).toBeUndefined();
  });

  test("without prune, a partial file list leaves the rest of the baseline intact", async () => {
    const target = makeDir();
    writeFileSync(join(target, "a.ts"), "a");
    writeFileSync(join(target, "b.ts"), "b");
    const store = new StateStore(join(target, "vigolium-results"));

    await store.recordFileSnapshot({
      targetDir: target,
      files: ["a.ts", "b.ts"],
      auditId: "audit-1",
      completedPhaseIds: ["L1"],
    });
    await store.recordFileSnapshot({
      targetDir: target,
      files: ["a.ts"],
      auditId: "audit-2",
      completedPhaseIds: ["L1"],
    });
    expect((await store.loadFileState()).files["b.ts"]).toBeDefined();
  });

  test("migrates a v1 file: last_phases becomes audit_phases, hashes survive", async () => {
    const target = makeDir();
    const resultsDir = join(target, "vigolium-results");
    mkdirSync(resultsDir, { recursive: true });
    writeFileSync(
      join(resultsDir, "file-state.json"),
      JSON.stringify({
        schema_version: 1,
        files: {
          "src/a.ts": { sha256: "deadbeef", last_audits: ["audit-1"], last_phases: ["D5", "D6"] },
        },
      }),
    );

    const state = await new StateStore(resultsDir).loadFileState();
    expect(state.schema_version).toBe(2);
    expect(state.files["src/a.ts"]!.sha256).toBe("deadbeef");
    expect(state.files["src/a.ts"]!.audit_phases).toEqual(["D5", "D6"]);
    expect((state.files["src/a.ts"] as Record<string, unknown>).last_phases).toBeUndefined();
  });

  test("rejects a file-state written by a newer build", async () => {
    const target = makeDir();
    const resultsDir = join(target, "vigolium-results");
    mkdirSync(resultsDir, { recursive: true });
    writeFileSync(
      join(resultsDir, "file-state.json"),
      JSON.stringify({ schema_version: 99, files: {} }),
    );
    await expect(new StateStore(resultsDir).loadFileState()).rejects.toThrow(/newer than this build/);
  });

  test("skips files that fail to read", async () => {
    const target = makeDir();
    writeFileSync(join(target, "exists.ts"), "y");
    const store = new StateStore(join(target, "vigolium-results"));

    await store.recordFileSnapshot({
      targetDir: target,
      files: ["exists.ts", "missing.ts"],
      auditId: "a",
      completedPhaseIds: ["Q"],
    });
    const state = await store.loadFileState();
    expect(state.files["exists.ts"]).toBeDefined();
    expect(state.files["missing.ts"]).toBeUndefined();
  });
});
