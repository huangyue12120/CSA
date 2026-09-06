#!/usr/bin/env node

import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

assert.equal(process.platform, 'linux', 'this acceptance fixture must run on Linux');
assert.ok(process.argv[2], 'usage: node scripts/test_linux_runtime.mjs <manager>');

function run(manager, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(manager, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (data) => {
      stdout += data;
    });
    child.stderr.on('data', (data) => {
      stderr += data;
    });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

function executable(pathname, contents) {
  writeFileSync(pathname, contents);
  chmodSync(pathname, 0o755);
}

const manager = path.resolve(process.argv[2]);
const temporary = mkdtempSync(path.join(os.tmpdir(), 'csa-linux-runtime-'));
try {
  const version = '1.2.3';
  const target = process.arch === 'x64' ? 'x86_64-unknown-linux-musl' : 'aarch64-unknown-linux-musl';
  const platformName = process.arch === 'x64' ? 'codex-linux-x64' : 'codex-linux-arm64';
  const modules = path.join(temporary, 'node_modules');
  const managed = path.join(modules, '@openai', 'codex');
  const platform = path.join(modules, '@openai', platformName);
  const runtime = path.join(platform, 'vendor', target);
  const launcher = path.join(managed, 'bin', 'codex');
  const native = path.join(runtime, 'bin', 'codex');
  const managerRoot = path.join(temporary, 'manager');
  const versionScript = `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf 'codex-cli ${version}\\n'
fi
`;

  mkdirSync(path.dirname(launcher), { recursive: true });
  mkdirSync(path.dirname(native), { recursive: true });
  mkdirSync(path.join(runtime, 'codex-resources', 'zsh', 'bin'), { recursive: true });
  mkdirSync(path.join(runtime, 'codex-path'), { recursive: true });
  writeFileSync(path.join(managed, 'package.json'), JSON.stringify({ name: '@openai/codex', version }));
  writeFileSync(path.join(platform, 'package.json'), JSON.stringify({ name: `@openai/${platformName}`, version }));
  writeFileSync(
    path.join(runtime, 'codex-package.json'),
    JSON.stringify({
      layoutVersion: 1,
      version,
      target,
      variant: 'codex',
      entrypoint: 'bin/codex',
      resourcesDir: 'codex-resources',
      pathDir: 'codex-path',
    }),
  );
  executable(launcher, versionScript);
  executable(native, versionScript);
  for (const relative of [
    'bin/codex-code-mode-host',
    'codex-resources/bwrap',
    'codex-resources/zsh/bin/zsh',
    'codex-path/rg',
  ]) {
    executable(path.join(runtime, relative), '#!/bin/sh\nexit 0\n');
  }

  const detected = await run(
    manager,
    ['doctor', '--json', '--manager-root', managerRoot, '--official', launcher],
    temporary,
  );
  assert.equal(detected.code, 0, detected.stderr);
  const report = JSON.parse(detected.stdout);
  assert.equal(report.official.version, version);
  assert.equal(report.official.runtime.package_manager, 'npm');
  assert.equal(report.official.runtime.files.length, 7);
  assert.equal(report.official.native.path, path.resolve(native));

  const env = await run(manager, ['shell', 'env', 'bash', '--manager-root', managerRoot], temporary);
  assert.equal(env.code, 0, env.stderr);
  assert.match(env.stdout, new RegExp(`${path.resolve(managerRoot, 'bin')}.*PATH`));
  const init = await run(manager, ['shell', 'init', 'zsh', '--manager-root', managerRoot], temporary);
  assert.equal(init.code, 0, init.stderr);
  assert.match(init.stdout, /csa\.sh/);

  rmSync(path.join(runtime, 'codex-resources', 'bwrap'));
  const incomplete = await run(
    manager,
    ['doctor', '--json', '--manager-root', path.join(temporary, 'invalid-manager'), '--official', launcher],
    temporary,
  );
  assert.equal(incomplete.code, 1, incomplete.stderr);
  assert.equal(JSON.parse(incomplete.stderr).error.code, 'official_runtime_incomplete');

  process.stdout.write(
    `${JSON.stringify({ schema: 1, runtime_discovery: 'pass', shell_activation: 'pass', helper_drift: 'pass' })}\n`,
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
