#!/usr/bin/env bun
/**
 * Multi-target build for vigolium-audit. Runs the content transform, regenerates the
 * embedded content bundle, then invokes `bun build --compile` for each target
 * triple. Output goes to dist/vigolium-audit-<target>.
 *
 * Usage:
 *   bun run build                 # current platform only
 *   bun run build --all           # all supported targets
 *   bun run build --target=bun-linux-x64
 */
import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync } from "fs";
import { homedir } from "os";
import { delimiter, dirname, join } from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";

const ROOT = dirname(fileURLToPath(import.meta.url));
const DIST = join(ROOT, "build", "dist");
const LOCAL_BIN = process.env.VIGOLIUM_AUDIT_BIN_DIR ?? join(homedir(), ".local", "bin");

// Bun has no `bun-windows-arm64` compile target, so windows ships x64 only.
// Windows on ARM runs x64 binaries under emulation, which covers those hosts.
const ALL_TARGETS = [
  "bun-darwin-arm64",
  "bun-darwin-x64",
  "bun-linux-arm64",
  "bun-linux-x64",
  "bun-windows-x64",
];

function detectCurrentTarget(): string {
  const arch = process.arch === "arm64" ? "arm64" : "x64";
  const platform =
    process.platform === "darwin"
      ? "darwin"
      : process.platform === "linux"
        ? "linux"
        : process.platform === "win32"
          ? "windows"
          : null;
  if (!platform) {
    throw new Error(`unsupported host platform: ${process.platform}`);
  }
  // Windows is x64-only (see ALL_TARGETS); an arm64 Windows host builds and
  // runs the x64 binary under emulation rather than failing outright.
  if (platform === "windows") return "bun-windows-x64";
  return `bun-${platform}-${arch}`;
}

/**
 * Name the compiled artifact for a target. Bun appends `.exe` itself when the
 * target is Windows, so the suffix is written explicitly here — otherwise the
 * path this script tracks (smoke test, local install, the staging script that
 * copies the blob into vigolium's go:embed path) would not be the path Bun
 * actually wrote.
 */
function outfileFor(target: string): string {
  const base = `vigolium-audit-${target.replace(/^bun-/, "")}`;
  return target.startsWith("bun-windows-") ? `${base}.exe` : base;
}

function runStep(label: string, cmd: string, args: string[]): void {
  console.log(`[build] ${label}`);
  const result = spawnSync(cmd, args, { cwd: ROOT, stdio: "inherit" });
  if (result.status !== 0) {
    throw new Error(`${label} failed (exit ${result.status})`);
  }
}

function main(): void {
  const argv = process.argv.slice(2);
  const all = argv.includes("--all");
  const targetArg = argv.find((a) => a.startsWith("--target="));
  const targets = all
    ? ALL_TARGETS
    : targetArg
      ? [targetArg.slice("--target=".length)]
      : [detectCurrentTarget()];

  if (existsSync(DIST)) rmSync(DIST, { recursive: true, force: true });
  mkdirSync(DIST, { recursive: true });

  runStep("transform content", "bun", ["run", "scripts/transform-content.ts"]);
  runStep("bundle content", "bun", ["run", "scripts/bundle-content.ts"]);

  const buildDate = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const commit = (() => {
    const r = spawnSync("git", ["rev-parse", "--short", "HEAD"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return r.status === 0 ? r.stdout.trim() : "unknown";
  })();

  let hostBinary: string | null = null;
  const hostTarget = (() => {
    try {
      return detectCurrentTarget();
    } catch {
      return null;
    }
  })();

  for (const target of targets) {
    const out = join(DIST, outfileFor(target));
    runStep(`compile ${target}`, "bun", [
      "build",
      "--compile",
      `--target=${target}`,
      "src/index.ts",
      `--outfile=${out}`,
      `--define`,
      `process.env.VIGOLIUM_AUDIT_BUILD_DATE="${buildDate}"`,
      `--define`,
      `process.env.VIGOLIUM_AUDIT_COMMIT="${commit}"`,
    ]);
    if (target === hostTarget) {
      smokeTest(out, { buildDate, commit });
      hostBinary = out;
    }
  }

  if (hostBinary && process.env.VIGOLIUM_AUDIT_BUILD_NO_INSTALL !== "1") {
    installToLocalBin(hostBinary);
  } else if (!hostBinary && targets.length > 0) {
    console.log(
      `[build] note: no host-platform binary built (host=${hostTarget ?? "?"}); skipping local install.`,
    );
  }
}

/**
 * Execute the freshly compiled host binary before anything installs or ships it.
 * A binary can compile cleanly and still be dead on arrival — `bun build` bundles
 * whatever is in node_modules, so source written against a newer dependency API
 * than the one installed throws at module load, before any command dispatches.
 *
 * `version` covers the happy path and proves the `--define` build metadata
 * actually reached the binary; the bogus subcommand covers the unknown-command
 * listener, which is registered at module top level.
 *
 * Only the host target can run here; cross-compiled binaries are left unchecked.
 */
function smokeTest(binary: string, meta: { buildDate: string; commit: string }): void {
  console.log(`[build] smoke ${binary}`);
  const fail = (what: string, r: ReturnType<typeof spawnSync>): never => {
    throw new Error(
      `smoke test failed: ${what} (exit ${r.status})\n${String(r.stdout ?? "")}${String(r.stderr ?? "")}`,
    );
  };

  const version = spawnSync(binary, ["version"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (version.status !== 0) fail("`version` did not exit 0", version);
  for (const expected of [`Build: ${meta.buildDate}`, `Commit: ${meta.commit}`]) {
    if (!version.stdout.includes(expected)) {
      fail(`\`version\` output is missing "${expected}" — --define did not reach the binary`, version);
    }
  }

  const unknown = spawnSync(binary, ["__build_smoke_unknown_command__"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (unknown.status !== 1) fail("an unknown subcommand did not exit 1", unknown);
}

function installToLocalBin(hostBinary: string): void {
  const onWindows = process.platform === "win32";
  try {
    mkdirSync(LOCAL_BIN, { recursive: true });
    const dst = join(LOCAL_BIN, onWindows ? "vigolium-audit.exe" : "vigolium-audit");
    copyFileSync(hostBinary, dst);
    // Windows has no execute bit — chmod there only toggles the read-only
    // flag, so skip it rather than clearing a bit that was never the point.
    if (!onWindows) chmodSync(dst, 0o755);
    console.log(`[build] installed → ${dst}`);
    if (!isOnPath(LOCAL_BIN)) {
      console.log(`[build] note: ${LOCAL_BIN} is not on PATH yet; add:`);
      console.log(
        onWindows
          ? `         setx PATH "${LOCAL_BIN};%PATH%"`
          : `         export PATH="${LOCAL_BIN}:$PATH"`,
      );
    }
  } catch (err) {
    console.warn(`[build] warn: failed to install to ${LOCAL_BIN}: ${(err as Error).message}`);
    console.warn(`[build] (set VIGOLIUM_AUDIT_BUILD_NO_INSTALL=1 to silence; VIGOLIUM_AUDIT_BIN_DIR=… to override)`);
  }
}

function isOnPath(dir: string): boolean {
  const p = process.env.PATH ?? "";
  // delimiter is ";" on Windows and ":" elsewhere — splitting on a hardcoded
  // ":" would treat a whole Windows PATH as one entry and always report "not
  // on PATH" (and a drive letter like C:\… would split mid-path).
  return p.split(delimiter).includes(dir);
}

main();
