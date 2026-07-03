import chalk from "chalk";
import { uninstallHarness } from "../engine/harness.js";

const PLATFORMS = ["claude", "codex"] as const;
type Platform = (typeof PLATFORMS)[number];

/**
 * Remove installed harness state. Pass a platform (claude|codex) to scope the
 * cleanup; omit it to remove every installed harness. `--agent <platform>`
 * resolves to the same positional in `index.ts`.
 */
export async function uninstallCommand(
  platform: string | undefined,
  opts: { json?: boolean } = {},
): Promise<void> {
  let targets: Platform[];
  if (platform === undefined) {
    targets = [...PLATFORMS];
  } else if (platform === "claude" || platform === "codex") {
    targets = [platform];
  } else {
    const msg = `platform must be "claude" or "codex" (or omit to remove all)`;
    if (opts.json) process.stdout.write(JSON.stringify({ ok: false, error: msg }) + "\n");
    else console.error(chalk.red(`error: ${msg}`));
    process.exit(2);
  }

  try {
    const removed: Record<string, string[]> = {};
    let total = 0;
    for (const p of targets) {
      const res = await uninstallHarness(p);
      removed[p] = res.removed;
      total += res.removed.length;
    }
    if (opts.json) {
      process.stdout.write(JSON.stringify({ ok: true, removed }) + "\n");
    } else if (total === 0) {
      console.log(`[vigolium-audit] nothing to remove for ${targets.join(", ")}`);
    } else {
      console.log(chalk.green(`[vigolium-audit] removed ${total} item(s):`));
      for (const p of targets) {
        for (const r of removed[p] ?? []) console.log(`  - ${r}`);
      }
    }
    process.exit(0);
  } catch (err) {
    if (opts.json) {
      process.stdout.write(JSON.stringify({ ok: false, error: (err as Error).message }) + "\n");
    } else {
      console.error(chalk.red(`[vigolium-audit] uninstall failed: ${(err as Error).message}`));
    }
    process.exit(1);
  }
}
