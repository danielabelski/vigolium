import chalk from "chalk";
import { installHarness, type SetupResult } from "../engine/harness.js";

const PLATFORMS = ["claude", "codex"] as const;
type Platform = (typeof PLATFORMS)[number];

/**
 * Persistent harness install. Copies the vendored content into each platform's
 * agent config dir:
 *   - claude → ~/.config/vigolium-audit/harness-claude/  (Claude Code plugin)
 *   - codex  → ~/.codex/agents/vigolium-audit-*.toml + ~/.codex/skills + AGENTS.md
 *
 * Unlike the ephemeral install that `run -i` performs (removed on exit), this
 * one stays put until `vigolium-audit uninstall`. Omit the platform to install both.
 */
export async function setupCommand(
  platform: string | undefined,
  opts: { json?: boolean } = {},
): Promise<void> {
  let targets: Platform[];
  if (platform === undefined) {
    targets = [...PLATFORMS];
  } else if (platform === "claude" || platform === "codex") {
    targets = [platform];
  } else {
    const msg = `platform must be "claude" or "codex" (or omit to install both)`;
    if (opts.json) process.stdout.write(JSON.stringify({ ok: false, error: msg }) + "\n");
    else console.error(chalk.red(`error: ${msg}`));
    process.exit(2);
  }

  try {
    const results: SetupResult[] = [];
    for (const p of targets) results.push(await installHarness(p));

    if (opts.json) {
      process.stdout.write(JSON.stringify({ ok: true, installed: results }) + "\n");
    } else {
      for (const r of results) {
        console.log(chalk.green(`[vigolium-audit] installed ${r.platform} harness → ${r.installPath}`));
        const parts = [
          `${r.agentsInstalled} agents`,
          `${r.commandsInstalled} commands`,
          `${r.skillsInstalled} skills`,
        ];
        if (r.excluded.length > 0) parts.push(`${r.excluded.length} excluded`);
        console.log(`  ${parts.join(", ")}`);
      }
    }
    process.exit(0);
  } catch (err) {
    if (opts.json) {
      process.stdout.write(JSON.stringify({ ok: false, error: (err as Error).message }) + "\n");
    } else {
      console.error(chalk.red(`[vigolium-audit] setup failed: ${(err as Error).message}`));
    }
    process.exit(1);
  }
}
