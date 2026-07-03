import { mkdtempSync, writeFileSync } from "fs";
import { homedir, tmpdir } from "os";
import { basename, join } from "path";
import { spawn, spawnSync } from "child_process";
import chalk from "chalk";
import { probeClaudeBinary, probeCodexBinary } from "../adapters/detect.js";
import { probeGit } from "../engine/git.js";
import { writeAuditContext } from "../engine/audit-context.js";
import { claudePluginDir, codexAgentsDir, registerEphemeralHarness } from "../engine/harness.js";
import type { AgentPlatform, AuditMode } from "../engine/types.js";
import { resolveModel } from "./run-models.js";
import { statusArrow, tildify } from "./util.js";

/**
 * Interactive mode (`-i` / `--interactive`).
 *
 * Drops the user into the underlying coding agent (claude / codex) with our
 * vigolium-audit plugin attached. We don't drive the SDK loop; we just hand off to
 * the native CLI in interactive mode so the user can drive the audit (resume,
 * edit prompts, run multiple modes) as themselves.
 *
 * With `--tmux`, the same handoff command runs inside a detached tmux session
 * whose pane output is streamed to our stdout; the user can `tmux attach` to
 * take over interactively.
 */
export async function runInteractive(args: {
  platform: AgentPlatform;
  mode: AuditMode;
  targetDir: string;
  noGit: boolean;
  tmux?: boolean;
  liveTarget?: string;
  model?: string;
  focus?: string;
  expectedBehaviors?: string;
  /** Override the agent binary/command (e.g. an env-wrapper like `cc`). */
  agentBinary?: string;
  /** claude-only: passed through as `--disallowedTools <value>`. */
  disallowedTools?: string;
}): Promise<void> {
  const { platform, mode, targetDir, noGit, liveTarget } = args;
  // Unset unless the user opted in (flag or VIGOLIUM_AUDIT_MODEL) so the agent
  // runtime uses its own configured default model.
  const effectiveModel = resolveModel(args.model);

  // Resolve the binary: an explicit --agent-binary wins over auto-detection.
  let binPath: string;
  if (args.agentBinary) {
    binPath = resolveAgentBinary(args.agentBinary);
  } else {
    const probe = platform === "claude" ? probeClaudeBinary() : probeCodexBinary();
    if (!probe.path) {
      const installHint =
        platform === "claude"
          ? "`npm i -g @anthropic-ai/claude-code` (or set VIGOLIUM_AUDIT_CLAUDE_PATH, or pass --agent-binary)"
          : "`npm i -g @openai/codex` (or set VIGOLIUM_AUDIT_CODEX_PATH, or pass --agent-binary)";
      console.error(chalk.red(`error: no \`${platform}\` binary found. Install via ${installHint}.`));
      process.exit(2);
    }
    binPath = probe.path;
  }

  const git = noGit
    ? { available: false, branch: null, commit: null, repository: null }
    : probeGit(targetDir);
  const tempDir = mkdtempSync(
    join(tmpdir(), `vigolium-audit-${new Date().toISOString().replace(/[:.]/g, "").slice(0, 15)}-`),
  );

  // Write `vigolium-results/audit-context.md` before the agent starts so the auto-confirm
  // directive (plus user-supplied focus / expected behaviors) lands in the
  // file the command-def Context block inlines via `!cat`. Matches the
  // headless ClaudeHandoff / CodexHandoff path. Without this, the agent never
  // sees the directive in interactive mode and is free to freelance text
  // confirmation prompts ("Two options: 1. Proceed / 2. Downshift…").
  await writeAuditContext(join(targetDir, "vigolium-results"), {
    ...(args.focus !== undefined ? { focus: args.focus } : {}),
    ...(args.expectedBehaviors !== undefined ? { expectedBehaviors: args.expectedBehaviors } : {}),
  });

  // Install the harness fresh for this run; remove it on exit (natural,
  // process.exit, default-SIGINT all fire `exit`). Leave-no-trace — unless a
  // persistent `vigolium-audit setup` install exists, which is preserved.
  const harness = await registerEphemeralHarness(platform);
  console.log(
    `[setup] installed ${harness.installResult.agentsInstalled} agents to ${tildify(harness.installResult.installPath)} (cleaned up on exit)`,
  );

  if (platform === "claude") {
    const pluginDir = claudePluginDir();
    const slashArgs = liveTarget !== undefined ? ` ${liveTarget}` : "";
    const slash = `/vigolium-audit:vigolium-audit:${mode}${slashArgs}`;
    const cmdArgs = ["--plugin-dir", pluginDir, "--dangerously-skip-permissions"];
    if (effectiveModel) cmdArgs.push("--model", effectiveModel);
    if (args.disallowedTools) cmdArgs.push("--disallowedTools", args.disallowedTools);

    printBanner({
      platform,
      mode,
      targetDir,
      gitAvailable: git.available,
      noGit,
      tempDir,
      command: `printf "${slash}" | ${tildify(binPath)} ${cmdArgs.map((a) => quote(tildify(a))).join(" ")}`,
    });

    if (args.tmux) {
      await execInTmux({ bin: binPath, args: cmdArgs, cwd: targetDir, stdinPayload: slash, tempDir });
      return;
    }
    await execInteractiveWithStdin({
      bin: binPath,
      args: cmdArgs,
      cwd: targetDir,
      stdinPayload: slash,
    });
    return;
  }

  // Codex: agents installed under ~/.codex/agents/vigolium-audit-*.toml. Codex has
  // no plugin-dir nor /slash-command system, so we just exec interactively
  // and instruct the user how to invoke the audit. (--disallowedTools has no
  // codex equivalent, so it's ignored here.)
  const codexAgents = codexAgentsDir();
  const cmdArgs: string[] = [];
  if (effectiveModel) cmdArgs.push("--model", effectiveModel);

  printBanner({
    platform,
    mode,
    targetDir,
    gitAvailable: git.available,
    noGit,
    tempDir,
    command: `${tildify(binPath)}    # then invoke @vigolium-audit:* agents in the session`,
    extraNotes: [
      `Codex agents available at ${tildify(codexAgents)} (prefix: vigolium-audit:*)`,
      `For "${mode}" mode, ask the agent: "Run an vigolium-audit ${mode} audit on this codebase."`,
    ],
  });

  if (args.tmux) {
    await execInTmux({ bin: binPath, args: cmdArgs, cwd: targetDir, stdinPayload: null, tempDir });
    return;
  }
  await execInteractiveWithStdin({
    bin: binPath,
    args: cmdArgs,
    cwd: targetDir,
    stdinPayload: null,
  });
}

/**
 * Resolve the user-supplied agent binary/command. Expands a leading `~/` to
 * the home directory; otherwise returns the value verbatim so a bare command
 * name (e.g. `cc`) is resolved via PATH by the OS at spawn time and an
 * absolute/relative path is used as-is.
 */
function resolveAgentBinary(bin: string): string {
  if (bin === "~") return homedir();
  if (bin.startsWith("~/")) return join(homedir(), bin.slice(2));
  return bin;
}

interface BannerArgs {
  platform: AgentPlatform;
  mode: AuditMode;
  targetDir: string;
  gitAvailable: boolean;
  noGit?: boolean;
  tempDir: string;
  command: string;
  extraNotes?: string[];
}

function printBanner(args: BannerArgs): void {
  const gitLabel = args.noGit
    ? "skipped (--no-git)"
    : args.gitAvailable
      ? "available"
      : "not available";
  console.log(`${statusArrow("Platform")} Platform:  ${args.platform}`);
  console.log(`${statusArrow("Mode")} Mode:      ${args.mode}`);
  console.log(`${statusArrow("Target")} Target:    ${tildify(args.targetDir)}`);
  console.log(`${statusArrow("Git")} Git:       ${gitLabel}`);
  console.log(`${statusArrow("Temp")} Temp:      ${tildify(args.tempDir)}`);
  console.log(`${statusArrow("Command")} Command:`);
  console.log(`  ${chalk.green(args.command)}`);
  for (const note of args.extraNotes ?? []) {
    console.log(`  ${note}`);
  }
  console.log("");
}

function quote(s: string): string {
  return /[\s"$`!]/.test(s) ? `"${s.replace(/"/g, '\\"')}"` : s;
}

/** POSIX single-quote a string for embedding in a `sh -c` / tmux command line. */
function shquote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function execInteractiveWithStdin(args: {
  bin: string;
  args: string[];
  cwd: string;
  /**
   * If set, write this string to the child's stdin then close it. Use null to
   * inherit the parent's stdin (full TTY interactive).
   */
  stdinPayload: string | null;
}): Promise<void> {
  const child = spawn(args.bin, args.args, {
    cwd: args.cwd,
    stdio: [args.stdinPayload === null ? "inherit" : "pipe", "inherit", "inherit"],
    env: process.env,
  });
  if (args.stdinPayload !== null && child.stdin) {
    child.stdin.write(args.stdinPayload);
    child.stdin.end();
  }
  const code: number = await new Promise((res, rej) => {
    child.on("error", rej);
    child.on("close", (c) => res(c ?? 0));
  });
  process.exit(code);
}

/**
 * Run the handoff command inside a detached tmux session and stream its pane
 * output to our stdout. The user can `tmux attach -t <session>` at any time to
 * take over interactively.
 *
 * The command runs directly as the session's command (not typed into an
 * interactive shell) so the stream carries only the agent's output — no shell
 * prompt or command echo. A short leading `sleep` gives us a window to attach
 * `pipe-pane` and register the `wait-for` channel before any output appears, so
 * a fast finish can't race the waiter or drop early lines; a trailing
 * `wait-for -S` signals completion.
 */
async function execInTmux(args: {
  bin: string;
  args: string[];
  cwd: string;
  stdinPayload: string | null;
  tempDir: string;
}): Promise<void> {
  if (spawnSync("tmux", ["-V"], { stdio: "ignore" }).error) {
    console.error(
      chalk.red("error: --tmux requires the `tmux` binary on PATH (install via your package manager)."),
    );
    process.exit(2);
  }

  // basename(tempDir) is already `vigolium-audit-<ts>-<rand>`, unique per run.
  const session = basename(args.tempDir).replace(/[^A-Za-z0-9_-]/g, "-");
  const doneChan = `${session}-done`;
  const logFile = join(args.tempDir, "tmux-output.log");
  writeFileSync(logFile, "");

  // Feed the slash payload (if any) via printf on stdin, run the agent, then
  // signal the wait-for channel on exit. tmux runs this string via /bin/sh.
  const pipeline =
    (args.stdinPayload !== null ? `printf %s ${shquote(args.stdinPayload)} | ` : "") +
    [args.bin, ...args.args].map(shquote).join(" ");
  const inner = `sleep 0.4; ${pipeline}; tmux wait-for -S ${doneChan}`;

  // Detached session in the target dir with a generous virtual pane so the
  // agent's output isn't wrapped at 80 cols.
  const created = spawnSync("tmux", [
    "new-session",
    "-d",
    "-s",
    session,
    "-c",
    args.cwd,
    "-x",
    "220",
    "-y",
    "50",
    inner,
  ]);
  if (created.status !== 0) {
    const stderr = created.stderr?.toString().trim();
    console.error(chalk.red(`error: failed to create tmux session${stderr ? `: ${stderr}` : ""}`));
    process.exit(1);
  }

  // Mirror everything the pane emits into the log file (-o = only while a
  // command is set, i.e. this one). Runs during the leading sleep, before output.
  spawnSync("tmux", ["pipe-pane", "-o", "-t", session, `cat >> ${shquote(logFile)}`]);

  console.log(
    chalk.blue(`[tmux] streaming session '${session}' — attach with: `) +
      chalk.bold(`tmux attach -t ${session}`),
  );
  console.log(chalk.gray(`[tmux] ${"─".repeat(60)}`));

  // Register the completion waiter (during the leading sleep, before any signal).
  const donePromise = new Promise<void>((res) => {
    const waiter = spawn("tmux", ["wait-for", doneChan], { stdio: "ignore" });
    waiter.on("close", () => res());
    waiter.on("error", () => res());
  });

  // Stream the pane log to our stdout.
  const tail = spawn("tail", ["-n", "+1", "-f", logFile], {
    stdio: ["ignore", "inherit", "inherit"],
  });

  await donePromise;

  // Let tail flush the final buffered pane output before we tear everything
  // down, then stop streaming and kill the session.
  await sleep(400);
  tail.kill();
  spawnSync("tmux", ["kill-session", "-t", session], { stdio: "ignore" });
  console.log(chalk.gray(`\n[tmux] ${"─".repeat(60)}`));
  console.log(chalk.blue(`[tmux] session '${session}' finished.`));
  process.exit(0);
}
