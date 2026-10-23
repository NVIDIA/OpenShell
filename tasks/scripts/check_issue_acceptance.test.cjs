// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const test = require('node:test');
const checkIssueAcceptance = require('./check_issue_acceptance.cjs');

async function check({
  permission = 'read', issues = [], body = '', permissionError,
  number = 7, headSha = 'pr-head', pullError, issueError, labelError,
} = {}) {
  const failures = [];
  const github = {
    rest: {
      pulls: {
        get: async ({ pull_number }) => {
          assert.equal(pull_number, number);
          if (pullError) throw new Error('PR lookup failed');
          return { data: {
            number, user: { login: 'contributor' }, head: { sha: headSha }, body,
          } };
        },
      },
      repos: {
        getCollaboratorPermissionLevel: async ({ username }) => {
          assert.equal(username, 'contributor');
          if (permissionError) throw Object.assign(new Error('lookup failed'), { status: permissionError });
          return { data: { permission } };
        },
        createCommitStatus() { assert.fail('PR decisions must not publish commit statuses'); },
      },
      issues: { listLabelsOnIssue() {} },
    },
    graphql: async (_query, variables) => {
      assert.equal(variables.number, number);
      if (issueError) throw new Error('Issue lookup failed');
      return { repository: { pullRequest: { closingIssuesReferences: {
        nodes: issues.map(issue => ({
          number: issue.number,
          url: `https://github.com/${issue.owner || 'NVIDIA'}/OpenShell/issues/${issue.number}`,
          repository: { name: 'OpenShell', owner: { login: issue.owner || 'NVIDIA' } },
        })),
        pageInfo: { hasNextPage: false, endCursor: null },
      } } } };
    },
    paginate: async (_method, { issue_number }) => {
      if (labelError) throw new Error('Label lookup failed');
      return issues.find(issue => issue.number === issue_number).labels || [];
    },
  };
  await checkIssueAcceptance({
    github,
    context: {
      repo: { owner: 'NVIDIA', repo: 'OpenShell' },
      payload: { pull_request: { number } },
      actor: 'maintainer', sha: 'base-commit', serverUrl: 'https://github.com', runId: 42,
    },
    core: { info() {}, setFailed: message => failures.push(message) },
  });
  return failures;
}

for (const permission of ['write', 'maintain', 'admin']) {
  test(`${permission} access allows an issue-less PR`, async () => {
    assert.deepEqual(await check({ permission }), []);
  });
}

for (const body of ['', 'No issue required: typo fix', '<!-- No issue required: example -->']) {
  test(`community PR without linked issues fails for body ${JSON.stringify(body)}`, async () => {
    const failures = await check({ body });
    assert.equal(failures.length, 1);
    assert.match(failures[0], /must link an issue with state:accepted/);
  });
}

test('all linked issues must be accepted, regardless of PR body or triggering actor', async () => {
  const failures = await check({
    body: 'No issue required: small fix',
    issues: [{ number: 1, labels: [{ name: 'state:accepted' }] }, { number: 2 }],
  });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /issues\/2/);
});

test('accepted issues in the target repository pass', async () => {
  assert.deepEqual(await check({ issues: [{ number: 1, labels: [{ name: 'state:accepted' }] }] }), []);
});

test('accepted issues in another repository cannot bypass the gate', async () => {
  const failures = await check({ issues: [{ number: 1, owner: 'contributor', labels: [{ name: 'state:accepted' }] }] });
  assert.equal(failures.length, 1);
  assert.match(failures[0], /Acceptance must be recorded in NVIDIA\/OpenShell/);
});

test('a non-collaborator still needs an accepted issue', async () => {
  assert.equal((await check({ permissionError: 404, body: 'No issue required: typo fix' })).length, 1);
});

test('permission lookup failures do not grant an exemption', async () => {
  await assert.rejects(check({ permissionError: 403 }), /lookup failed/);
});

for (const [option, message] of [
  ['pullError', /PR lookup failed/],
  ['issueError', /Issue lookup failed/],
  ['labelError', /Label lookup failed/],
]) {
  test(`${option} fails the workflow invocation`, async () => {
    await assert.rejects(check({ [option]: true, issues: [{ number: 1 }] }), message);
  });
}

test('PRs sharing a head SHA evaluate their own issue references in either order', async () => {
  const rejected = { number: 7, headSha: 'shared-head', issues: [{ number: 1 }] };
  const accepted = {
    number: 8, headSha: 'shared-head',
    issues: [{ number: 2, labels: [{ name: 'state:accepted' }] }],
  };
  for (const pair of [[rejected, accepted], [accepted, rejected]]) {
    const results = await Promise.all(pair.map(input => check(input)));
    pair.forEach((input, index) => {
      assert.equal(results[index].length, input.number === 7 ? 1 : 0);
    });
  }
});

test('a failed refresh rejects after an earlier successful evaluation', async () => {
  assert.deepEqual(await check({ permission: 'write' }), []);
  await assert.rejects(check({ permission: 'write', pullError: true }), /PR lookup failed/);
});
