// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  compareVersions,
  parsePrereleaseTag,
  parseStableTag,
  selectPreviousStable,
} from './codex-security-release-range.mjs';

const SCRIPT = fileURLToPath(
  new URL('./codex-security-release-range.mjs', import.meta.url),
);

function git(repository, ...args) {
  return execFileSync('git', args, {
    cwd: repository,
    encoding: 'utf8',
  }).trim();
}

function commit(repository, name) {
  writeFileSync(join(repository, 'content.txt'), `${name}\n`, {
    encoding: 'utf8',
  });
  git(repository, 'add', 'content.txt');
  git(
    repository,
    '-c',
    'user.name=Codex Security Test',
    '-c',
    'user.email=codex-security-test@example.com',
    'commit',
    '-m',
    name,
  );
}

function createRepository() {
  const repository = mkdtempSync(join(tmpdir(), 'codex-security-range-'));
  git(repository, 'init', '--initial-branch=main');
  return repository;
}

function runResolver(repository, ...args) {
  return JSON.parse(
    execFileSync(process.execPath, [SCRIPT, ...args], {
      cwd: repository,
      encoding: 'utf8',
    }),
  );
}

test('parses strict stable and prerelease tags', () => {
  assert.deepEqual(parseStableTag('v0.1.0'), {
    tag: 'v0.1.0',
    version: [0, 1, 0],
  });
  assert.equal(parseStableTag('v0.1.0-pre.1'), null);
  assert.equal(parseStableTag('dev'), null);
  assert.equal(parseStableTag('v01.1.0'), null);

  assert.deepEqual(parsePrereleaseTag('v2.10.3-pre.12'), {
    tag: 'v2.10.3-pre.12',
    version: [2, 10, 3],
    prerelease: 12,
    train: 'v2.10.3',
  });
  assert.equal(parsePrereleaseTag('v2.10.3'), null);
  assert.equal(parsePrereleaseTag('v2.10.3-pre.0'), null);
});

test('selects the newest stable strictly before the candidate train', () => {
  assert.equal(
    selectPreviousStable(
      [
        'v0.1.9',
        'v0.1.10',
        'v0.2.0-pre.1',
        'v0.2.0',
        'vm-runtime',
      ],
      [0, 2, 0],
    ),
    'v0.1.10',
  );
  assert.equal(selectPreviousStable(['v0.1.0'], [0, 1, 0]), undefined);
  assert(compareVersions([0, 10, 0], [0, 2, 99]) > 0);
});

test('resolves a cumulative prerelease range from Git history', () => {
  const repository = createRepository();
  try {
    commit(repository, 'stable');
    git(repository, 'tag', 'v0.1.0');
    commit(repository, 'pre one');
    git(repository, 'tag', 'v0.1.1-pre.1');
    commit(repository, 'pre two');
    git(repository, 'tag', 'v0.1.1-pre.2');
    git(
      repository,
      'update-ref',
      'refs/remotes/origin/main',
      git(repository, 'rev-parse', 'HEAD'),
    );

    const result = runResolver(
      repository,
      '--candidate',
      'v0.1.1-pre.2',
    );
    assert.equal(result.base_tag, 'v0.1.0');
    assert.equal(result.candidate_tag, 'v0.1.1-pre.2');
    assert.equal(result.train, 'v0.1.1');
    assert.equal(result.category, 'codex-security/v0.1.1');
    assert.equal(result.scan_scope, 'diff');
    assert.equal(result.commit_count, '2');
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test('rejects a prerelease that is not on main', () => {
  const repository = createRepository();
  try {
    commit(repository, 'stable');
    git(repository, 'tag', 'v0.1.0');
    git(
      repository,
      'update-ref',
      'refs/remotes/origin/main',
      git(repository, 'rev-parse', 'HEAD'),
    );
    git(repository, 'switch', '--create', 'detached-release');
    commit(repository, 'off-main candidate');
    git(repository, 'tag', 'v0.1.1-pre.1');

    const result = spawnSync(
      process.execPath,
      [SCRIPT, '--candidate', 'v0.1.1-pre.1'],
      { cwd: repository, encoding: 'utf8' },
    );
    assert.equal(result.status, 1);
    assert.match(result.stderr, /is not an ancestor of origin\/main/);
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});

test('requires explicit approval before a full bootstrap scan', () => {
  const repository = createRepository();
  try {
    commit(repository, 'first candidate');
    git(repository, 'tag', 'v0.1.0-pre.1');
    git(
      repository,
      'update-ref',
      'refs/remotes/origin/main',
      git(repository, 'rev-parse', 'HEAD'),
    );

    const rejected = spawnSync(
      process.execPath,
      [SCRIPT, '--candidate', 'v0.1.0-pre.1'],
      { cwd: repository, encoding: 'utf8' },
    );
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /--allow-full-bootstrap/);

    const approved = runResolver(
      repository,
      '--candidate',
      'v0.1.0-pre.1',
      '--allow-full-bootstrap',
    );
    assert.equal(approved.scan_scope, 'full');
    assert.equal(approved.base_tag, '');
    assert.equal(approved.train, 'v0.1.0');
  } finally {
    rmSync(repository, { recursive: true, force: true });
  }
});
