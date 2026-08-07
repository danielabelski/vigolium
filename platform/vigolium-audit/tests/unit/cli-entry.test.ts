import { describe, expect, test } from "bun:test";
import { resolve } from "path";
import pkg from "../../package.json" with { type: "json" };

/**
 * Happy-path coverage for the CLI entry module itself.
 *
 * Everything in `src/index.ts` above `cli.parse()` — global options, the help
 * renderer, the `command:*` listener — runs at module load, so a mismatch with
 * the installed `cac` API kills every subcommand at once, `--version` included.
 * The rest of the suite only asserts *rejection* paths, which a dead entry point
 * can still satisfy by exiting non-zero for the wrong reason.
 */
const CLI_ENTRY = resolve(import.meta.dir, "../../src/index.ts");

async function runCli(args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["bun", "run", CLI_ENTRY, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "" },
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { exitCode, stdout, stderr };
}

describe("CLI entry point", () => {
  test("`version` prints the version block on stdout and exits 0", async () => {
    const { exitCode, stdout } = await runCli(["version"]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain(`Version: v${pkg.version}`);
    expect(stdout).toContain("Build: ");
    expect(stdout).toContain("Commit: ");
  });

  test("`--version` matches the `version` subcommand", async () => {
    const flag = await runCli(["--version"]);
    const sub = await runCli(["version"]);
    expect(flag.exitCode).toBe(0);
    expect(flag.stdout).toContain(`Version: v${pkg.version}`);
    expect(flag.stdout.split("\n").filter((l) => !l.startsWith("Build: "))).toEqual(
      sub.stdout.split("\n").filter((l) => !l.startsWith("Build: ")),
    );
  });

  test("no arguments prints help and exits 0", async () => {
    const { exitCode, stdout } = await runCli([]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("vigolium-audit run");
  });

  test("an unknown subcommand exits 1 with guidance", async () => {
    const { exitCode, stderr } = await runCli(["definitely-not-a-command"]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("unknown command 'definitely-not-a-command'");
    expect(stderr).toContain("Available commands:");
  });

  test("a near-miss subcommand suggests the real one", async () => {
    const { exitCode, stderr } = await runCli(["runn"]);
    expect(exitCode).toBe(1);
    expect(stderr).toContain("did you mean 'run'?");
  });
});
