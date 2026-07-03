#!/usr/bin/env bun
/**
 * Dependency upgrade helper — `bun run upgrade`.
 *
 * The agent SDKs (`@anthropic-ai/claude-agent-sdk`, `@openai/codex-sdk`) are
 * version-coupled to the CLI binaries they drive over the stdio control
 * protocol: when the vendored SDK drifts far behind the installed `claude` /
 * `codex` binary, SDK-driven headless runs can truncate mid-audit (see
 * `src/adapters/version-check.ts`). Plain `bun update` only moves within the
 * declared caret range, so it can't cross a minor bump like `0.2 -> 0.3` — the
 * exact gap that caused the truncation this script exists to prevent.
 *
 * So this pins both SDKs to `@latest` (crossing minor/major), refreshes the
 * rest of the tree within range, and reports whether the result lines up with
 * the installed CLI binaries.
 *
 * Flags:
 *   --sdks-only   only bump the two agent SDKs; skip the general `bun update`
 *   --dry-run     print the commands that would run without changing anything
 */
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";
import { probeClaudeBinary, probeCodexBinary } from "../src/adapters/detect.js";
import { detectClaudeVersionDrift, probeClaudeBinaryVersion } from "../src/adapters/version-check.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The version-coupled agent SDKs, bumped to @latest to track their CLI binaries. */
const SDKS = ["@anthropic-ai/claude-agent-sdk", "@openai/codex-sdk"];

const cyan = (s: string): string => `\x1b[36m${s}\x1b[0m`;
const yellow = (s: string): string => `\x1b[33m${s}\x1b[0m`;
const green = (s: string): string => `\x1b[32m${s}\x1b[0m`;
const dim = (s: string): string => `\x1b[2m${s}\x1b[0m`;
const PREFIX = cyan("[upgrade]");

const args = new Set(process.argv.slice(2));
const dryRun = args.has("--dry-run");
const sdksOnly = args.has("--sdks-only");

function step(msg: string): void {
  console.log(`${PREFIX} ${msg}`);
}

function run(cmd: string, cmdArgs: string[]): void {
  const printable = `${cmd} ${cmdArgs.join(" ")}`;
  if (dryRun) {
    console.log(`${dim("would run:")} ${printable}`);
    return;
  }
  step(printable);
  const result = spawnSync(cmd, cmdArgs, { cwd: ROOT, stdio: "inherit" });
  if (result.status !== 0) {
    throw new Error(`\`${printable}\` failed (exit ${result.status})`);
  }
}

/** Read a field off an installed dependency's package.json (fresh from disk). */
function installedField(pkg: string, field: string): string | null {
  try {
    const p = join(ROOT, "node_modules", pkg, "package.json");
    const json = JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>;
    const v = json[field];
    return typeof v === "string" && v.length > 0 ? v : null;
  } catch {
    return null;
  }
}

// 1. Bump the version-coupled SDKs to @latest (crosses minor/major; a plain
//    `bun update` can't). `bun add` rewrites the caret ranges in package.json.
run("bun", ["add", ...SDKS.map((s) => `${s}@latest`)]);

// 2. Refresh everything else within its declared range (unless --sdks-only).
if (!sdksOnly) {
  run("bun", ["update"]);
}

if (dryRun) {
  console.log(`\n${PREFIX} ${dim("dry run — nothing changed")}`);
  process.exit(0);
}

// 3. Report alignment with the installed CLI binaries.
console.log(`\n${PREFIX} versions after upgrade:`);

// Claude: the SDK declares the claude-code release its control-protocol bridge
// targets, so we can do a real drift check against the installed binary.
const claudeSdkVer = installedField("@anthropic-ai/claude-agent-sdk", "version");
const claudeTarget = installedField("@anthropic-ai/claude-agent-sdk", "claudeCodeVersion");
const claudeBinVer = probeClaudeBinaryVersion(probeClaudeBinary().path ?? "");
const claudeDrift = detectClaudeVersionDrift(claudeTarget, claudeBinVer);
console.log(
  `  claude   SDK ${cyan(claudeSdkVer ?? "?")} ${dim(`(targets claude-code ${claudeTarget ?? "?"})`)} ` +
    `vs binary ${cyan(claudeBinVer ?? "not found")}  ` +
    (claudeDrift
      ? yellow("⚠ drift — SDK-driven headless runs may still truncate")
      : green("✓ aligned")),
);

// Codex: the SDK exposes no target-binary field, so this is informational only.
const codexSdkVer = installedField("@openai/codex-sdk", "version");
const codexBinVer = probeClaudeBinaryVersion(probeCodexBinary().path ?? "");
console.log(
  `  codex    SDK ${cyan(codexSdkVer ?? "?")} vs binary ${cyan(codexBinVer ?? "not found")}  ` +
    dim("(informational — codex SDK declares no target binary version)"),
);

console.log(
  `\n${PREFIX} next: ${cyan("bun run preflight")} to verify, then ${cyan("bun run build")} to reinstall ` +
    dim("(the compiled binary must be rebuilt to ship the new SDK)"),
);
if (claudeDrift) {
  console.log(
    `${PREFIX} ${yellow("note:")} the claude binary is still out of range for the latest SDK; ` +
      `a newer SDK release may not exist yet, or your binary is ahead of it.`,
  );
}
