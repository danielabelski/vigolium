import { spawnSync } from "child_process";
import sdkPkg from "@anthropic-ai/claude-agent-sdk/package.json" with { type: "json" };

/**
 * Version-coupling guard for the claude SDK adapter.
 *
 * `ClaudeSdkAdapter` drives the user's `claude` binary over the Agent SDK's
 * stdio *control protocol* (subagent lifecycle, hooks, permissions, MCP all
 * flow over it). That bridge ships inside `@anthropic-ai/claude-agent-sdk` and
 * is built for one specific claude-code release — pinned in the SDK's own
 * package.json as `claudeCodeVersion`. When the installed binary drifts far
 * enough from that target, the newer binary can emit control messages the
 * vendored bridge doesn't understand ("Unknown message type" → ConnectionClosed),
 * which terminates an SDK-driven headless audit mid-run. Interactive (`-i`) and
 * the `--print` CLI adapter both speak the binary's *own* native protocol, so
 * they're immune — which is why only headless SDK runs truncate.
 *
 * This module surfaces a startup warning when that drift is large enough to
 * risk it, so the failure can't recur silently after a future `claude` update.
 */

/**
 * The claude-code version the *vendored* Agent SDK bridge targets. Read via a
 * build-time JSON import so the value is inlined into the compiled binary
 * (matching `src/index.ts`'s own-version import) rather than read from a
 * node_modules tree that doesn't exist post-`bun build --compile`.
 */
export function sdkTargetClaudeVersion(): string | null {
  const v = (sdkPkg as { claudeCodeVersion?: unknown }).claudeCodeVersion;
  return typeof v === "string" && v.length > 0 ? v : null;
}

/**
 * Run `<bin> --version` and parse the leading semver. Claude prints e.g.
 * `2.1.199 (Claude Code)`. Returns null on any failure (missing binary,
 * non-zero exit, unparseable output) — the guard is advisory and must never
 * block a run.
 */
export function probeClaudeBinaryVersion(binPath: string): string | null {
  try {
    const res = spawnSync(binPath, ["--version"], {
      encoding: "utf8",
      timeout: 5000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    if (res.status !== 0) return null;
    const m = /(\d+)\.(\d+)\.(\d+)/.exec(res.stdout ?? "");
    return m ? m[0] : null;
  } catch {
    return null;
  }
}

interface Semver {
  major: number;
  minor: number;
  patch: number;
}

function parseSemver(v: string): Semver | null {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(v);
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

export interface VersionDrift {
  /** claude-code version the vendored SDK bridge targets. */
  sdkTarget: string;
  /** Version of the `claude` binary that will actually be spawned. */
  binary: string;
}

/**
 * Patch gap (same major.minor) beyond which we warn. The SDK's release cadence
 * lags the CLI, so small patch drift is normal and expected; warning on every
 * patch bump would be pure noise. The empirically-observed truncation happened
 * across a ~58-patch gap (SDK target 2.1.141 vs binary 2.1.199), so a threshold
 * an order of magnitude below that catches real drift without crying wolf.
 */
const PATCH_DRIFT_THRESHOLD = 10;

/**
 * Compare the vendored SDK's target claude-code version against the installed
 * binary. Returns a {@link VersionDrift} when the gap is large enough to risk
 * control-protocol incompatibility — a differing major/minor, or a large patch
 * gap within the same major.minor — else null.
 */
export function detectClaudeVersionDrift(
  sdkTarget: string | null,
  binary: string | null,
): VersionDrift | null {
  if (!sdkTarget || !binary) return null;
  const a = parseSemver(sdkTarget);
  const b = parseSemver(binary);
  if (!a || !b) return null;
  const majorMinorDiffers = a.major !== b.major || a.minor !== b.minor;
  const largePatchGap = Math.abs(a.patch - b.patch) >= PATCH_DRIFT_THRESHOLD;
  return majorMinorDiffers || largePatchGap ? { sdkTarget, binary } : null;
}
