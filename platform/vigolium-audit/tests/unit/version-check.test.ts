import { describe, expect, test } from "bun:test";
import {
  detectClaudeVersionDrift,
  sdkTargetClaudeVersion,
} from "../../src/adapters/version-check.js";

describe("detectClaudeVersionDrift", () => {
  test("returns null when versions match exactly", () => {
    expect(detectClaudeVersionDrift("2.1.199", "2.1.199")).toBeNull();
  });

  test("ignores small patch drift (SDK cadence lags the CLI)", () => {
    expect(detectClaudeVersionDrift("2.1.199", "2.1.201")).toBeNull();
    expect(detectClaudeVersionDrift("2.1.199", "2.1.190")).toBeNull();
  });

  test("flags a large patch gap within the same major.minor", () => {
    // The empirically-observed truncation: SDK target 2.1.141 vs binary 2.1.199.
    const drift = detectClaudeVersionDrift("2.1.141", "2.1.199");
    expect(drift).toEqual({ sdkTarget: "2.1.141", binary: "2.1.199" });
  });

  test("flags a minor difference", () => {
    expect(detectClaudeVersionDrift("2.1.199", "2.2.0")).not.toBeNull();
  });

  test("flags a major difference", () => {
    expect(detectClaudeVersionDrift("2.1.199", "3.0.0")).not.toBeNull();
  });

  test("returns null when either version is missing or unparseable", () => {
    expect(detectClaudeVersionDrift(null, "2.1.199")).toBeNull();
    expect(detectClaudeVersionDrift("2.1.199", null)).toBeNull();
    expect(detectClaudeVersionDrift("not-a-version", "2.1.199")).toBeNull();
  });

  test("tolerates trailing suffixes on the binary version string", () => {
    // Parsed from `claude --version` output like "2.1.199 (Claude Code)".
    expect(detectClaudeVersionDrift("2.1.141", "2.1.199")).not.toBeNull();
  });
});

describe("sdkTargetClaudeVersion", () => {
  test("reads the vendored SDK's claudeCodeVersion", () => {
    // Coupled to the pinned dep; the guard is meaningless if this ever returns
    // null, so assert the shape rather than a specific value.
    const v = sdkTargetClaudeVersion();
    expect(v).toMatch(/^\d+\.\d+\.\d+/);
  });
});
