#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { execFileSync, spawnSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';

const STABLE_TAG_RE =
  /^v(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)$/;
const PRERELEASE_TAG_RE =
  /^v(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)-pre\.(?<prerelease>[1-9]\d*)$/;

function versionFromMatch(match) {
  return [
    Number(match.groups.major),
    Number(match.groups.minor),
    Number(match.groups.patch),
  ];
}

export function parseStableTag(tag) {
  const match = STABLE_TAG_RE.exec(tag);
  if (match === null) return null;
  return { tag, version: versionFromMatch(match) };
}

export function parsePrereleaseTag(tag) {
  const match = PRERELEASE_TAG_RE.exec(tag);
  if (match === null) return null;
  const version = versionFromMatch(match);
  return {
    tag,
    version,
    prerelease: Number(match.groups.prerelease),
    train: `v${version.join('.')}`,
  };
}

export function compareVersions(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

export function selectPreviousStable(tags, candidateVersion) {
  return tags
    .map(parseStableTag)
    .filter(
      (parsed) =>
        parsed !== null &&
        compareVersions(parsed.version, candidateVersion) < 0,
    )
    .sort((left, right) => compareVersions(right.version, left.version))[0]?.tag;
}

function parseArguments(argv) {
  const options = {
    candidate: '',
    stable: '',
    mainRef: 'origin/main',
    allowFullBootstrap: false,
    githubOutput: process.env.GITHUB_OUTPUT ?? '',
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case '--candidate':
        options.candidate = argv[++index] ?? '';
        break;
      case '--stable':
        options.stable = argv[++index] ?? '';
        break;
      case '--main-ref':
        options.mainRef = argv[++index] ?? '';
        break;
      case '--allow-full-bootstrap':
        options.allowFullBootstrap = true;
        break;
      case '--github-output':
        options.githubOutput = argv[++index] ?? '';
        break;
      default:
        throw new Error(`unknown argument: ${argument}`);
    }
  }

  if (options.candidate === '') {
    throw new Error('--candidate is required');
  }
  if (options.mainRef === '') {
    throw new Error('--main-ref must not be empty');
  }
  return options;
}

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8' }).trim();
}

function resolvesToCommit(ref) {
  try {
    return git(['rev-parse', '--verify', `${ref}^{commit}`]);
  } catch {
    throw new Error(`Git reference does not resolve to a commit: ${ref}`);
  }
}

function isAncestor(ancestor, descendant) {
  const result = spawnSync(
    'git',
    ['merge-base', '--is-ancestor', ancestor, descendant],
    { stdio: 'ignore' },
  );
  if (result.status === 0) return true;
  if (result.status === 1) return false;
  throw new Error(
    `git merge-base failed for ${ancestor} and ${descendant} (exit ${result.status ?? 'unknown'})`,
  );
}

function writeOutputs(path, outputs) {
  if (path === '') return;
  const lines = Object.entries(outputs).map(([key, value]) => `${key}=${value}`);
  appendFileSync(path, `${lines.join('\n')}\n`, { encoding: 'utf8' });
}

function resolveRange(options) {
  const candidate = parsePrereleaseTag(options.candidate);
  if (candidate === null) {
    throw new Error(
      `candidate must match vMAJOR.MINOR.PATCH-pre.N: ${options.candidate}`,
    );
  }

  const candidateSha = resolvesToCommit(candidate.tag);
  const mainSha = resolvesToCommit(options.mainRef);
  if (!isAncestor(candidateSha, mainSha)) {
    throw new Error(
      `candidate ${candidate.tag} (${candidateSha}) is not an ancestor of ${options.mainRef}`,
    );
  }

  const mergedTags = git(['tag', '--list', 'v*', '--merged', candidateSha])
    .split('\n')
    .filter(Boolean);
  const stableTag =
    options.stable || selectPreviousStable(mergedTags, candidate.version);

  if (stableTag === undefined || stableTag === '') {
    if (!options.allowFullBootstrap) {
      throw new Error(
        `no previous stable tag exists for ${candidate.tag}; rerun with an approved base or --allow-full-bootstrap`,
      );
    }

    return {
      base_tag: '',
      base_sha: '',
      candidate_tag: candidate.tag,
      candidate_sha: candidateSha,
      train: candidate.train,
      category: `codex-security/${candidate.train}`,
      scan_scope: 'full',
      commit_count: git(['rev-list', '--count', candidateSha]),
    };
  }

  const stable = parseStableTag(stableTag);
  if (stable === null) {
    throw new Error(
      `stable base must match vMAJOR.MINOR.PATCH without a prerelease: ${stableTag}`,
    );
  }
  if (compareVersions(stable.version, candidate.version) >= 0) {
    throw new Error(
      `stable base ${stable.tag} must be older than release train ${candidate.train}`,
    );
  }

  const stableSha = resolvesToCommit(stable.tag);
  if (!isAncestor(stableSha, candidateSha)) {
    throw new Error(
      `stable base ${stable.tag} (${stableSha}) is not an ancestor of ${candidate.tag}`,
    );
  }

  const commitCount = Number(
    git(['rev-list', '--count', `${stableSha}..${candidateSha}`]),
  );
  if (!Number.isSafeInteger(commitCount) || commitCount <= 0) {
    throw new Error(
      `candidate ${candidate.tag} has no commits after stable base ${stable.tag}`,
    );
  }

  return {
    base_tag: stable.tag,
    base_sha: stableSha,
    candidate_tag: candidate.tag,
    candidate_sha: candidateSha,
    train: candidate.train,
    category: `codex-security/${candidate.train}`,
    scan_scope: 'diff',
    commit_count: String(commitCount),
  };
}

function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    const outputs = resolveRange(options);
    writeOutputs(options.githubOutput, outputs);
    process.stdout.write(`${JSON.stringify(outputs, null, 2)}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (process.env.GITHUB_ACTIONS === 'true') {
      process.stderr.write(`::error::${message}\n`);
    } else {
      process.stderr.write(`codex-security-release-range: ${message}\n`);
    }
    process.exitCode = 1;
  }
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === new URL(process.argv[1], 'file:').href
) {
  main();
}
