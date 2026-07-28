import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawnSync } from "child_process";
import { cloneRemoteTarget, isRemoteTargetUrl, normalizeRemote } from "../../src/cli/clone-target.js";
import { parseCloneDepth } from "../../src/cli/util.js";

describe("isRemoteTargetUrl", () => {
  test("https GitHub URL → remote", () => {
    expect(isRemoteTargetUrl("https://github.com/Yoast/wordpress-seo")).toBe(true);
  });
  test("https GitLab URL → remote", () => {
    expect(isRemoteTargetUrl("https://gitlab.com/owner/repo")).toBe(true);
  });
  test("https URL with .git suffix → remote", () => {
    expect(isRemoteTargetUrl("https://github.com/owner/repo.git")).toBe(true);
  });
  test("http (insecure) URL → remote", () => {
    expect(isRemoteTargetUrl("http://forge.internal/owner/repo")).toBe(true);
  });
  test("git:// URL → remote", () => {
    expect(isRemoteTargetUrl("git://host.example/owner/repo.git")).toBe(true);
  });
  test("ssh:// URL → remote", () => {
    expect(isRemoteTargetUrl("ssh://git@host.example/owner/repo.git")).toBe(true);
  });
  test("scp-style git@host:owner/repo → remote", () => {
    expect(isRemoteTargetUrl("git@github.com:owner/repo.git")).toBe(true);
  });
  test("plain relative path → local", () => {
    expect(isRemoteTargetUrl("./repo")).toBe(false);
  });
  test("absolute path → local", () => {
    expect(isRemoteTargetUrl("/tmp/repo")).toBe(false);
  });
  test("bare name → local", () => {
    expect(isRemoteTargetUrl("repo")).toBe(false);
  });
  test("empty string → false", () => {
    expect(isRemoteTargetUrl("")).toBe(false);
  });
  test("colon-less user@host → local (not a clonable URL)", () => {
    expect(isRemoteTargetUrl("user@host")).toBe(false);
  });
});

describe("normalizeRemote", () => {
  test("strips trailing .git", () => {
    expect(normalizeRemote("https://github.com/o/r.git")).toBe("https://github.com/o/r");
  });
  test("strips trailing slash", () => {
    expect(normalizeRemote("https://github.com/o/r/")).toBe("https://github.com/o/r");
  });
  test("strips trailing slash then .git", () => {
    expect(normalizeRemote("https://github.com/o/r.git/")).toBe("https://github.com/o/r");
  });
  test("no-op when already normal", () => {
    expect(normalizeRemote("https://github.com/o/r")).toBe("https://github.com/o/r");
  });
});

/** Init a bare "remote" repo (3 commits) we can clone from without network access. */
function makeBareRepo(): { url: string; cleanup: () => void } {
  const root = mkdtempSync(join(tmpdir(), "vigolium-audit-clone-test-fixture-"));
  const work = join(root, "work");
  const remote = join(root, "remote.git");
  mkdirSync(work);
  spawnSync("git", ["init", "-q", "-b", "main", work], { stdio: "ignore" });
  spawnSync("git", ["-C", work, "config", "user.email", "test@example.com"], { stdio: "ignore" });
  spawnSync("git", ["-C", work, "config", "user.name", "Test"], { stdio: "ignore" });
  for (let i = 1; i <= 3; i++) {
    writeFileSync(join(work, "README.md"), `hello ${i}\n`);
    spawnSync("git", ["-C", work, "add", "."], { stdio: "ignore" });
    spawnSync("git", ["-C", work, "commit", "-q", "-m", `commit ${i}`], { stdio: "ignore" });
  }
  spawnSync("git", ["clone", "--bare", work, remote], { stdio: "ignore" });
  return {
    url: remote,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

/** Count commits reachable from HEAD in a checkout. */
function commitCount(dir: string): number {
  const r = spawnSync("git", ["-C", dir, "rev-list", "--count", "HEAD"], { encoding: "utf8" });
  return Number(r.stdout.trim());
}

describe("cloneRemoteTarget", () => {
  test("clones into ./<slug>/ under cwd, then reuses on a second call", () => {
    const fixture = makeBareRepo();
    const originalCwd = process.cwd();
    process.chdir(mkdtempSync(join(tmpdir(), "vigolium-audit-clone-target-cwd-")));
    // process.cwd() may differ from the mkdtempSync return value on macOS
    // (mkdtempSync returns /var/..., process.cwd() returns /private/var/...).
    // Use process.cwd() as the source of truth to avoid symlink false-negatives.
    const cwd = process.cwd();
    try {
      const first = cloneRemoteTarget(fixture.url);
      expect(first.reused).toBe(false);
      // The local-path bare repo has no owner/host so repoSlug falls back to
      // the basename ("remote.git" → "remote" after .git strip). What matters
      // is the directory is created under cwd and contains the README.
      expect(first.clonedTargetDir.startsWith(cwd)).toBe(true);
      expect(
        spawnSync("test", ["-f", join(first.clonedTargetDir, "README.md")]).status,
      ).toBe(0);

      const second = cloneRemoteTarget(fixture.url);
      expect(second.reused).toBe(true);
      expect(second.clonedTargetDir).toBe(first.clonedTargetDir);
    } finally {
      process.chdir(originalCwd);
      rmSync(cwd, { recursive: true, force: true });
      fixture.cleanup();
    }
  });

  test("refuses to clobber a non-empty non-git directory", () => {
    const fixture = makeBareRepo();
    const originalCwd = process.cwd();
    process.chdir(mkdtempSync(join(tmpdir(), "vigolium-audit-clone-target-clobber-")));
    const cwd = process.cwd();
    try {
      // Pre-create the slug directory with foreign content.
      const slug = "remote";
      mkdirSync(join(cwd, slug));
      writeFileSync(join(cwd, slug, "leftover"), "x");
      expect(() => cloneRemoteTarget(fixture.url)).toThrow(/non-empty but not a git checkout/);
    } finally {
      process.chdir(originalCwd);
      rmSync(cwd, { recursive: true, force: true });
      fixture.cleanup();
    }
  });

  test("default clone is shallow (depth 10 reported in the summary)", () => {
    const fixture = makeBareRepo();
    const originalCwd = process.cwd();
    process.chdir(mkdtempSync(join(tmpdir(), "vigolium-audit-clone-target-depth-")));
    const cwd = process.cwd();
    try {
      const result = cloneRemoteTarget(fixture.url);
      expect(result.summary).toMatch(/depth=10/);
    } finally {
      process.chdir(originalCwd);
      rmSync(cwd, { recursive: true, force: true });
      fixture.cleanup();
    }
  });

  test("explicit depth truncates history to that many commits", () => {
    const fixture = makeBareRepo();
    const originalCwd = process.cwd();
    process.chdir(mkdtempSync(join(tmpdir(), "vigolium-audit-clone-target-depth1-")));
    const cwd = process.cwd();
    try {
      // file:// forces the git-aware transport so --depth is honored; a plain
      // local path would be hardlink-cloned and ignore --depth.
      const result = cloneRemoteTarget(`file://${fixture.url}`, { depth: 1 });
      expect(result.summary).toMatch(/depth=1\b/);
      expect(commitCount(result.clonedTargetDir)).toBe(1);
    } finally {
      process.chdir(originalCwd);
      rmSync(cwd, { recursive: true, force: true });
      fixture.cleanup();
    }
  });

  test("depth 0 clones full history", () => {
    const fixture = makeBareRepo();
    const originalCwd = process.cwd();
    process.chdir(mkdtempSync(join(tmpdir(), "vigolium-audit-clone-target-full-")));
    const cwd = process.cwd();
    try {
      const result = cloneRemoteTarget(`file://${fixture.url}`, { depth: 0 });
      expect(result.summary).toMatch(/full history/);
      // The fixture has 3 commits; a full clone sees all of them.
      expect(commitCount(result.clonedTargetDir)).toBe(3);
    } finally {
      process.chdir(originalCwd);
      rmSync(cwd, { recursive: true, force: true });
      fixture.cleanup();
    }
  });
});

describe("parseCloneDepth", () => {
  test("positive integer string → number", () => {
    expect(parseCloneDepth("50")).toBe(50);
  });
  test("numeric input passes through", () => {
    expect(parseCloneDepth(25)).toBe(25);
  });
  test("0 → full clone sentinel", () => {
    expect(parseCloneDepth("0")).toBe(0);
  });
  test('"full" → 0', () => {
    expect(parseCloneDepth("full")).toBe(0);
  });
  test('"unshallow"/"all" (any case) → 0', () => {
    expect(parseCloneDepth("Unshallow")).toBe(0);
    expect(parseCloneDepth("ALL")).toBe(0);
  });
  test("negative → null", () => {
    expect(parseCloneDepth("-5")).toBeNull();
  });
  test("non-integer → null", () => {
    expect(parseCloneDepth("2.5")).toBeNull();
  });
  test("junk → null", () => {
    expect(parseCloneDepth("deep")).toBeNull();
  });
});
