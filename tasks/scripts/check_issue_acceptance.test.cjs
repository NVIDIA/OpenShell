// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const test = require('node:test');
const checkIssueAcceptance = require('./check_issue_acceptance.cjs');

async function check({
  permission = 'read', issues = [], body = '', permissionError,
  number = 7, headSha = 'pr-head', pullError, issueError, labelError,
  draft = false, state = 'open', drafts = [], draftError,
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
            node_id: `pr-node-${number}`, draft, state,
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
    graphql: async (query, variables) => {
      if (query.includes('convertPullRequestToDraft')) {
        assert.equal(variables.pullRequestId, `pr-node-${number}`);
        drafts.push(variables.pullRequestId);
        if (draftError) throw new Error('Draft conversion failed');
        return { convertPullRequestToDraft: { pullRequest: { isDraft: true } } };
      }
      assert.match(query, /closingIssuesReferences/);
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
    const drafts = [];
    assert.deepEqual(await check({ permission, drafts }), []);
    assert.deepEqual(drafts, []);
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
  const drafts = [];
  assert.deepEqual(await check({ drafts, issues: [{ number: 1, labels: [{ name: 'state:accepted' }] }] }), []);
  assert.deepEqual(drafts, []);
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
  const drafts = [];
  await assert.rejects(check({ permissionError: 403, drafts }), /lookup failed/);
  assert.deepEqual(drafts, []);
});

for (const [option, message] of [
  ['pullError', /PR lookup failed/],
  ['issueError', /Issue lookup failed/],
  ['labelError', /Label lookup failed/],
]) {
  test(`${option} fails the workflow invocation`, async () => {
    const drafts = [];
    await assert.rejects(check({ [option]: true, issues: [{ number: 1 }], drafts }), message);
    assert.deepEqual(drafts, []);
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

for (const issues of [
  [],
  [{ number: 1 }],
  [{ number: 1, labels: [{ name: 'state:accepted' }] }, { number: 2 }],
  [{ number: 1, owner: 'contributor', labels: [{ name: 'state:accepted' }] }],
]) {
  test(`rejected ready PR converts to draft for issues ${JSON.stringify(issues)}`, async () => {
    const drafts = [];
    assert.equal((await check({ issues, drafts })).length, 1);
    assert.deepEqual(drafts, ['pr-node-7']);
  });
}

test('an already-draft PR still fails acceptance without another conversion', async () => {
  const drafts = [];
  assert.equal((await check({ draft: true, drafts })).length, 1);
  assert.deepEqual(drafts, []);
});

test('accepted draft PRs stay draft', async () => {
  const drafts = [];
  assert.deepEqual(await check({
    draft: true, drafts, issues: [{ number: 1, labels: [{ name: 'state:accepted' }] }],
  }), []);
  assert.deepEqual(drafts, []);
});

test('closed PRs are left alone using current metadata', async () => {
  const drafts = [];
  assert.deepEqual(await check({ state: 'closed', drafts, permissionError: 403 }), []);
  assert.deepEqual(drafts, []);
});

test('draft conversion errors fail the workflow invocation', async () => {
  await assert.rejects(check({ draftError: true }), /Draft conversion failed/);
});
