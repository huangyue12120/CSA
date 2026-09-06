#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const launcher = path.resolve(repository, 'npm', 'meta', 'bin', 'csa.js');
const meta = JSON.parse(readFileSync(path.resolve(repository, 'npm', 'meta', 'package.json'), 'utf8'));
const matrix = JSON.parse(readFileSync(path.resolve(repository, 'npm', 'meta', 'platforms.json'), 'utf8'));
const linuxPlatforms = matrix.platforms.filter((platform) => platform.os === 'linux');
assert.deepEqual(
  linuxPlatforms.map((platform) => platform.target),
  ['x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl'],
);
assert.ok(linuxPlatforms.every((platform) => !Object.hasOwn(platform, 'libc')));
const selected = matrix.platforms.find(
  (platform) => platform.os === process.platform && platform.arch === process.arch,
);
assert.ok(selected, `test host ${process.platform}-${process.arch} is unsupported`);

async function testProcessGroupSignal(env, cwd) {
  if (process.platform === 'win32') {
    return 'not_verified_on_windows';
  }
  const child = spawn(
    process.execPath,
    [launcher, '-e', 'process.stdout.write("ready\\n");setInterval(() => {}, 1000)'],
    { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let timer;
  try {
    await Promise.race([
      new Promise((resolveReady, rejectReady) => {
        child.stdout.once('data', (data) => {
          if (data.toString().includes('ready')) resolveReady();
          else rejectReady(new Error(`unexpected signal probe output: ${data}`));
        });
        child.once('exit', (code, signal) =>
          rejectReady(new Error(`signal probe exited early: code=${code} signal=${signal}`)),
        );
      }),
      new Promise((_, rejectTimeout) => {
        timer = setTimeout(() => rejectTimeout(new Error('signal probe startup timed out')), 5000);
      }),
    ]);
    clearTimeout(timer);
    const closed = new Promise((resolveClose) =>
      child.once('close', (code, signal) => resolveClose({ code, signal })),
    );
    process.kill(-child.pid, 'SIGTERM');
    const outcome = await Promise.race([
      closed,
      new Promise((_, rejectTimeout) => {
        timer = setTimeout(() => rejectTimeout(new Error('signal probe shutdown timed out')), 5000);
      }),
    ]);
    assert.equal(outcome.code, null);
    assert.equal(outcome.signal, 'SIGTERM');
    return 'pass';
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) {
      process.kill(-child.pid, 'SIGKILL');
    }
  }
}

function runLauncher(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [launcher, ...args], {
      ...options,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
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
    child.once('close', (status, signal) => resolve({ status, signal, stdout, stderr }));
  });
}

async function testTopLevelSignal(env, cwd) {
  if (process.platform === 'win32') {
    return 'not_verified_on_windows';
  }
  const child = spawn(
    process.execPath,
    [launcher, '-e', 'process.stdout.write("ready\\n");setInterval(() => {}, 1000)'],
    { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let timer;
  try {
    await Promise.race([
      new Promise((resolveReady, rejectReady) => {
        child.stdout.once('data', (data) => {
          if (data.toString().includes('ready')) resolveReady();
          else rejectReady(new Error(`unexpected signal probe output: ${data}`));
        });
        child.once('exit', (code, signal) =>
          rejectReady(new Error(`signal probe exited early: code=${code} signal=${signal}`)),
        );
      }),
      new Promise((_, rejectTimeout) => {
        timer = setTimeout(() => rejectTimeout(new Error('top-level signal probe startup timed out')), 5000);
      }),
    ]);
    clearTimeout(timer);
    const closed = new Promise((resolveClose) =>
      child.once('close', (code, signal) => resolveClose({ code, signal })),
    );
    process.kill(child.pid, 'SIGTERM');
    const outcome = await Promise.race([
      closed,
      new Promise((_, rejectTimeout) => {
        timer = setTimeout(() => rejectTimeout(new Error('top-level signal probe shutdown timed out')), 5000);
      }),
    ]);
    assert.equal(outcome.code, null);
    assert.equal(outcome.signal, 'SIGTERM');
    return 'pass';
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) {
      process.kill(child.pid, 'SIGKILL');
    }
  }
}

const temporary = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'csa-launcher-')));
try {
  const stagedRoot = path.join(temporary, 'stage');
  const probeBinary = path.join(temporary, 'platform-probe');
  if (process.platform !== 'win32') {
    writeFileSync(
      probeBinary,
      `#!/bin/sh
case "$1" in
  -e)
    case "$2" in
      *JSON.stringify*)
        printf '{"args":["space value","--literal=$()"],"cwd":"%s","marker":"%s"}' "$PWD" "$CSA_LAUNCHER_MARKER"
        printf 'stderr-ok' >&2
        ;;
      *setInterval*)
        printf 'ready\\n'
        while :; do sleep 1; done
        ;;
      *process.exit\\(37\\)*)
        exit 37
        ;;
    esac
    ;;
esac
`,
    );
    chmodSync(probeBinary, 0o755);
  }
  const platformBinary = process.platform === 'win32' ? process.execPath : probeBinary;
  const staged = spawnSync(
    process.execPath,
    [
      path.resolve(repository, 'scripts', 'stage_npm_packages.mjs'),
      '--out',
      stagedRoot,
      '--binary',
      `${selected.id}=${platformBinary}`,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(staged.status, 0, staged.stderr || staged.stdout);
  if (process.platform !== 'win32') {
    assert.notEqual(
      statSync(path.join(stagedRoot, 'meta', 'bin', 'csa.js')).mode & 0o111,
      0,
    );
  }
  const sourceRepository = { type: 'git', url: 'https://github.com/DSLZL/CSA' };
  assert.deepEqual(
    JSON.parse(readFileSync(path.join(stagedRoot, 'meta', 'package.json'), 'utf8')).repository,
    sourceRepository,
  );
  assert.deepEqual(
    JSON.parse(
      readFileSync(path.join(stagedRoot, 'platforms', selected.id, 'package.json'), 'utf8'),
    ).repository,
    sourceRepository,
  );

  const packageRoot = path.join(temporary, 'node_modules', ...selected.package.split('/'));
  const binary = path.resolve(packageRoot, selected.binary);
  mkdirSync(path.dirname(binary), { recursive: true });
  copyFileSync(platformBinary, binary);
  if (process.platform !== 'win32') {
    chmodSync(binary, 0o755);
  }
  const sha256 = createHash('sha256').update(readFileSync(binary)).digest('hex');
  const platformManifest = {
    name: selected.package,
    version: meta.version,
    csa: {
      schema: 1,
      target: selected.target,
      binary: selected.binary,
      sha256,
    },
  };
  const manifestPath = path.join(packageRoot, 'package.json');
  writeFileSync(manifestPath, `${JSON.stringify(platformManifest, null, 2)}\n`);

  const env = {
    ...process.env,
    NODE_PATH: path.join(temporary, 'node_modules'),
    CSA_LAUNCHER_MARKER: 'marker value',
  };
  const probe = [
    '-e',
    'process.stdout.write(JSON.stringify({args:process.argv.slice(1),cwd:process.cwd(),marker:process.env.CSA_LAUNCHER_MARKER}));process.stderr.write("stderr-ok")',
    '--',
    'space value',
    '--literal=$()',
  ];
  const forwarded = await runLauncher(probe, {
    cwd: temporary,
    env,
  });
  assert.equal(forwarded.status, 0, forwarded.stderr);
  assert.equal(forwarded.stderr, 'stderr-ok');
  assert.deepEqual(JSON.parse(forwarded.stdout), {
    args: ['space value', '--literal=$()'],
    cwd: temporary,
    marker: 'marker value',
  });

  const exit = await runLauncher(['-e', 'process.exit(37)'], {
    env,
  });
  assert.equal(exit.status, 37);
  const signal = await testProcessGroupSignal(env, temporary);
  const topLevelSignal = await testTopLevelSignal(env, temporary);

  platformManifest.csa.sha256 = '0'.repeat(64);
  writeFileSync(manifestPath, `${JSON.stringify(platformManifest, null, 2)}\n`);
  const drift = await runLauncher(['--version'], { env });
  assert.equal(drift.status, 1);
  assert.match(drift.stderr, /checksum mismatch/);

  rmSync(packageRoot, { recursive: true, force: true });
  const missing = await runLauncher(['--version'], { env });
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /required platform package .* is not installed/);

  process.stdout.write(
    `${JSON.stringify({ schema: 1, argv_env_cwd_stdio: 'pass', exit_code: 'pass', checksum_drift: 'pass', missing_platform: 'pass', signal, top_level_signal: topLevelSignal }, null, 2)}\n`,
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
