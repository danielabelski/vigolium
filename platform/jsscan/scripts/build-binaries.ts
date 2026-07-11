#!/usr/bin/env bun

import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sourceFingerprint } from './source-fingerprint';

interface Target {
  id: string;
  bunTarget: string;
  outfile: string;
  os: NodeJS.Platform;
  arch: string;
}

const targets: Target[] = [
  { id: 'linux-amd64', bunTarget: 'bun-linux-x64', outfile: 'jsscan-linux-amd64', os: 'linux', arch: 'x64' },
  { id: 'linux-arm64', bunTarget: 'bun-linux-arm64', outfile: 'jsscan-linux-arm64', os: 'linux', arch: 'arm64' },
  { id: 'darwin-amd64', bunTarget: 'bun-darwin-x64', outfile: 'jsscan-darwin-amd64', os: 'darwin', arch: 'x64' },
  { id: 'darwin-arm64', bunTarget: 'bun-darwin-arm64', outfile: 'jsscan-darwin-arm64', os: 'darwin', arch: 'arm64' },
  { id: 'windows-amd64', bunTarget: 'bun-windows-x64', outfile: 'jsscan-windows-amd64.exe', os: 'win32', arch: 'x64' },
];

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')) as {
  version: string;
  dependencies?: Record<string, string>;
};

function selectedTargets(): Target[] {
  const args = process.argv.slice(2);
  if (args.includes('--all')) return targets;
  const targetArg = args.find((arg) => arg.startsWith('--target='));
  if (targetArg) {
    const id = targetArg.slice('--target='.length);
    const target = targets.find((item) => item.id === id);
    if (!target) throw new Error(`unsupported jsscan target: ${id}`);
    return [target];
  }
  if (args.includes('--host')) {
    const target = targets.find((item) => item.os === process.platform && item.arch === process.arch);
    if (!target) throw new Error(`unsupported host: ${process.platform}/${process.arch}`);
    return [target];
  }
  throw new Error('pass --host, --all, or --target=<os>-<arch>');
}

const hash = await sourceFingerprint();
const timestamp = process.env.SOURCE_DATE_EPOCH
  ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString()
  : '';
const commit = process.env.JSSCAN_GIT_COMMIT ?? '';
const definitions = {
  __JSSCAN_SOURCE_HASH__: JSON.stringify(hash),
  __JSSCAN_TOOL_VERSION__: JSON.stringify(pkg.version),
  __JSSCAN_BUILD_TIMESTAMP__: JSON.stringify(timestamp),
  __JSSCAN_GIT_COMMIT__: JSON.stringify(commit),
  __JSSCAN_DEPENDENCIES__: JSON.stringify(JSON.stringify(pkg.dependencies ?? {})),
};

for (const target of selectedTargets()) {
  const args = [
    'bun', 'build', 'src/cli.ts', '--compile', `--target=${target.bunTarget}`,
    '--external', 'isolated-vm', '--outfile', join('bin', target.outfile),
  ];
  for (const [name, value] of Object.entries(definitions)) {
    args.push('--define', `${name}=${value}`);
  }
  const child = Bun.spawn(args, { cwd: root, stdout: 'inherit', stderr: 'inherit', stdin: 'inherit' });
  const exitCode = await child.exited;
  if (exitCode !== 0) process.exit(exitCode);
}
