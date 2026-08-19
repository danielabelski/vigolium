#!/usr/bin/env node
// Unified entry point for the Vigolium CLI distributed via npm.
//
// The platform-specific binary is shipped *gzipped* inside an optional
// dependency package (one of @vigolium/vigolium-<tag>). On first run we
// decompress it once into a version-scoped cache directory and then exec it,
// forwarding args, stdio, signals and the exit status.

import { spawn } from "node:child_process";
import { createReadStream, createWriteStream, existsSync, statSync } from "node:fs";
import { mkdir, rename, chmod, unlink } from "node:fs/promises";
import { createRequire } from "node:module";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// __dirname / require equivalents in ESM.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

// Local alias (npm install path) -> nothing else; the underlying package
// published to npm is always @vigolium/vigolium with a version suffix.
const PLATFORM_PACKAGE_BY_TAG = {
  "linux-x64": "@vigolium/vigolium-linux-x64",
  "linux-arm64": "@vigolium/vigolium-linux-arm64",
  "darwin-x64": "@vigolium/vigolium-darwin-x64",
  "darwin-arm64": "@vigolium/vigolium-darwin-arm64",
  "windows-x64": "@vigolium/vigolium-windows-x64",
};

const { platform, arch } = process;

function detectPackageManager() {
  const userAgent = process.env.npm_config_user_agent || "";
  if (/\bbun\//.test(userAgent)) return "bun";
  const execPath = process.env.npm_execpath || "";
  if (execPath.includes("bun")) return "bun";
  return userAgent ? "npm" : null;
}

function reinstallHint() {
  return detectPackageManager() === "bun"
    ? "bun install -g @vigolium/vigolium@latest"
    : "npm install -g @vigolium/vigolium@latest";
}

let platformTag = null;
switch (platform) {
  case "linux":
  case "android":
    if (arch === "x64") platformTag = "linux-x64";
    else if (arch === "arm64") platformTag = "linux-arm64";
    break;
  case "darwin":
    if (arch === "x64") platformTag = "darwin-x64";
    else if (arch === "arm64") platformTag = "darwin-arm64";
    break;
  case "win32":
    // Windows ships x64 only — the embedded vigolium-audit and jstangle
    // helpers are `bun build --compile` outputs and Bun has no
    // bun-windows-arm64 target. An arm64 Windows host gets the x64 build and
    // runs it under emulation, which is why the windows platform package
    // declares both CPUs (see build/npm/build.mjs).
    if (arch === "x64" || arch === "arm64") platformTag = "windows-x64";
    break;
  default:
    break;
}

if (!platformTag) {
  throw new Error(
    `Unsupported platform: ${platform} (${arch}). ` +
      `Vigolium npm builds cover linux/darwin on x64/arm64 and windows on x64. ` +
      `See https://docs.vigolium.com for other install options.`,
  );
}

const platformPackage = PLATFORM_PACKAGE_BY_TAG[platformTag];

// Resolve the gzipped binary: prefer the installed optional-dependency
// package, fall back to a local vendor/ tree (used by `npm pack` testing and
// in-repo dev before publishing).
const gzName = "vigolium.gz";
const localVendorRoot = path.join(__dirname, "..", "vendor");
const localGzPath = path.join(localVendorRoot, platformTag, gzName);

let gzPath = null;
try {
  const pkgJsonPath = require.resolve(`${platformPackage}/package.json`);
  gzPath = path.join(path.dirname(pkgJsonPath), "vendor", platformTag, gzName);
} catch {
  if (existsSync(localGzPath)) {
    gzPath = localGzPath;
  }
}

if (!gzPath || !existsSync(gzPath)) {
  throw new Error(
    `Missing platform package ${platformPackage} (the vigolium binary for ` +
      `${platformTag} was not installed). This usually means npm skipped ` +
      `optional dependencies. Reinstall Vigolium:\n    ${reinstallHint()}`,
  );
}

// Version-scoped cache path so upgrades never exec a stale binary, and so the
// extraction directory is always writable by the running user even when the
// package itself was installed into a root-owned global prefix.
const pkgVersion = require("../package.json").version;
const vigoliumHome =
  process.env.VIGOLIUM_HOME || path.join(os.homedir(), ".vigolium");
const binaryDir = path.join(vigoliumHome, "npm-bin", pkgVersion, platformTag);
// Windows resolves executability from the file extension, not a permission
// bit: an extensionless file cannot be spawned at all, so the .exe suffix is
// required rather than cosmetic.
const isWindows = platform === "win32";
const binaryPath = path.join(binaryDir, isWindows ? "vigolium.exe" : "vigolium");

async function ensureBinary() {
  if (existsSync(binaryPath) && statSync(binaryPath).size > 0) {
    return;
  }

  await mkdir(binaryDir, { recursive: true });

  // Decompress to a unique temp file, then atomically rename into place so
  // concurrent first-runs and interrupted extractions can never leave a
  // truncated binary at the final path.
  const tmpPath = path.join(
    binaryDir,
    `vigolium.${process.pid}.${Date.now()}.tmp`,
  );

  try {
    await pipeline(
      createReadStream(gzPath),
      createGunzip(),
      createWriteStream(tmpPath, { mode: 0o755 }),
    );
    // Windows has no execute bit — chmod there only toggles the read-only
    // flag, so skip it rather than clearing a bit that was never the point.
    if (!isWindows) await chmod(tmpPath, 0o755);
    await rename(tmpPath, binaryPath);
  } catch (err) {
    await unlink(tmpPath).catch(() => {});
    // Another racing process may have completed the extraction already. This
    // is the normal path on Windows rather than a rare race: the rename fails
    // outright whenever another vigolium process holds the destination open
    // for execution. The cache dir is version- and platform-scoped, so an
    // existing non-empty binary there is the same build we just unpacked.
    if (existsSync(binaryPath) && statSync(binaryPath).size > 0) {
      return;
    }
    throw new Error(
      `Failed to unpack the vigolium binary for ${platformTag}: ${err.message}\n` +
        `Try reinstalling:\n    ${reinstallHint()}`,
    );
  }
}

await ensureBinary();

// Use an asynchronous spawn (not spawnSync) so Node can respond to signals
// (e.g. Ctrl-C / SIGINT) while the native binary runs, forward them to the
// child, and mirror the child's termination reason in the parent.
// spawn can fail *synchronously* (e.g. ENOEXEC when the unpacked binary does
// not match the host), which the "error" handler below never sees — that one
// only catches asynchronous failures. Without this try/catch the user gets a
// raw Node stack trace instead of something actionable.
let child;
try {
  child = spawn(binaryPath, process.argv.slice(2), {
    stdio: "inherit",
    env: process.env,
  });
} catch (err) {
  console.error(
    `Failed to execute the vigolium binary for ${platformTag} at ${binaryPath}: ${err.message}\n` +
      `The unpacked binary may be corrupt or built for a different platform. ` +
      `Remove ${binaryDir} and reinstall:\n    ${reinstallHint()}`,
  );
  process.exit(1);
}

child.on("error", (err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});

const forwardSignal = (signal) => {
  if (child.killed) return;
  try {
    child.kill(signal);
  } catch {
    /* ignore */
  }
};

["SIGINT", "SIGTERM", "SIGHUP"].forEach((sig) => {
  process.on(sig, () => forwardSignal(sig));
});

const childResult = await new Promise((resolve) => {
  child.on("exit", (code, signal) => {
    if (signal) {
      resolve({ type: "signal", signal });
    } else {
      resolve({ type: "code", exitCode: code ?? 1 });
    }
  });
});

if (childResult.type === "signal") {
  // Re-emit the same signal so the parent terminates with 128 + n semantics.
  process.kill(process.pid, childResult.signal);
} else {
  process.exit(childResult.exitCode);
}
