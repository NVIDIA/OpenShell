// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const test = require('node:test');
const checkIssueAcceptance = require('./check_issue_acceptance.cjs');

async function check({ permission = 'read', issues = [], body = '', permissionError } = {}) {
  const failures = [];
  const statuses = [];
  const github = {
    rest: {
      pulls: {
        get: async () => ({ data: {
          number: 7, user: { login: 'contributor' }, head: { sha: 'pr-head' }, body,
        } }),
      },
      repos: {
        getCollaboratorPermissionLevel: async ({ username }) => {
          assert.equal(username, 'contributor');
          if (permissionError) throw Object.assign(new Error('lookup failed'), { status: permissionError });
          return { data: { permission } };
        },
        createCommitStatus: async status => { statuses.push(status); },
      },
      issues: { listLabelsOnIssue() {} },
    },
    graphql: async () => ({ repository: { pullRequest: { closingIssuesReferences: {
      nodes: issues.map(issue => ({
        number: issue.number,
        url: `https://github.com/${issue.owner || 'NVIDIA'}/OpenShell/issues/${issue.number}`,
        repository: { name: 'OpenShell', owner: { login: issue.owner || 'NVIDIA' } },
      })),
      pageInfo: { hasNextPage: false, endCursor: null },
    } } } }),
    paginate: async (_method, { issue_number }) => issues.find(issue => issue.number === issue_number).labels || [],
  };
  await checkIssueAcceptance({
    github,
    context: {
      repo: { owner: 'NVIDIA', repo: 'OpenShell' },
      payload: { pull_request: { number: 7 } },
      actor: 'maintainer', sha: 'base-commit', serverUrl: 'https://github.com', runId: 42,
    },
    core: { info() {}, setFailed: message => failures.push(message) },
  });
  assert.deepEqual(statuses.map(status => status.state), ['pending', failures.length ? 'failure' : 'success']);
  assert(statuses.every(status => status.sha === 'pr-head' && status.context === 'PR Issue Acceptance'));
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
