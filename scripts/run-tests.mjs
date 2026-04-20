#!/usr/bin/env node

import { existsSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';

const args = process.argv.slice(2);

if (args.includes('--ensure-node-modules')) {
  if (existsSync('node_modules')) process.exit(0);
  const npmArgs = ['install', '--prefer-offline', '--no-audit', '--no-fund'];
  const npmCli = process.env.npm_execpath || (
    process.platform === 'win32'
      ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
      : null
  );
  const result = npmCli
    ? spawnSync(process.execPath, [npmCli, ...npmArgs], { stdio: 'inherit' })
    : spawnSync('npm', npmArgs, { stdio: 'inherit' });
  if (result.error) {
    process.stderr.write(`${result.error.message}\n`);
  }
  process.exit(result.status ?? 1);
}

const roots = [];
const nodeArgs = [];

for (let i = 0; i < args.length; i += 1) {
  if (args[i] === '--root') {
    roots.push(args[++i]);
  } else if (args[i] === '--roots') {
    roots.push(...args[++i].split(',').filter(Boolean));
  } else {
    nodeArgs.push(args[i]);
  }
}

if (roots.length === 0) {
  process.stderr.write('Usage: run-tests.mjs --root <dir> [node --test args]\n');
  process.exit(1);
}

const files = [];

function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(path);
    } else if (entry.isFile() && entry.name.endsWith('.test.js')) {
      files.push(path);
    }
  }
}

for (const root of roots) walk(root);
files.sort();

const result = spawnSync(process.execPath, ['--test', ...nodeArgs, ...files], {
  stdio: 'inherit',
});
process.exit(result.status ?? 1);
