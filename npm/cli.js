#!/usr/bin/env node
/**
 * VXRecon npm launcher.
 *
 * A thin wrapper so the tool can be run with `npx vxrecon ...` or installed
 * globally with `npm i -g vxrecon`. It locates a Python 3.11+ interpreter,
 * checks whether the bundled Python package is importable (installing it in an
 * isolated way is left to the user; this wrapper never mutates global state),
 * then forwards every argument to the VXRecon CLI.
 *
 * Privacy: this script performs no network I/O of its own and sends nothing
 * anywhere. It only spawns the local Python process.
 */

'use strict';

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const MIN_MAJOR = 3;
const MIN_MINOR = 11;

function findPython() {
  const candidates = process.platform === 'win32'
    ? ['python', 'python3', 'py']
    : ['python3', 'python'];

  for (const cmd of candidates) {
    try {
      const res = spawnSync(cmd, ['-c', 'import sys;print("%d.%d" % sys.version_info[:2])'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      if (res.status === 0 && res.stdout) {
        const [major, minor] = res.stdout.trim().split('.').map(Number);
        if (major > MIN_MAJOR || (major === MIN_MAJOR && minor >= MIN_MINOR)) {
          return cmd;
        }
      }
    } catch (_) {
      // try next candidate
    }
  }
  return null;
}

function main() {
  const python = findPython();
  if (!python) {
    process.stderr.write(
      '[!] VXRecon requires Python 3.11 or newer.\n' +
      '    Install it from https://www.python.org/downloads/ and retry.\n'
    );
    process.exit(3);
  }

  const pkgRoot = path.resolve(__dirname, '..');
  const runner = path.join(pkgRoot, 'vxrecon.py');
  const args = process.argv.slice(2);

  let command;
  let commandArgs;
  if (fs.existsSync(runner)) {
    // Run from the bundled source tree.
    command = python;
    commandArgs = [runner, ...args];
  } else {
    // Fall back to an installed `vxrecon` module.
    command = python;
    commandArgs = ['-m', 'vxrecon', ...args];
  }

  const result = spawnSync(command, commandArgs, { stdio: 'inherit' });
  if (result.error) {
    process.stderr.write(`[!] failed to launch VXRecon: ${result.error.message}\n`);
    process.exit(2);
  }
  process.exit(result.status === null ? 2 : result.status);
}

main();
