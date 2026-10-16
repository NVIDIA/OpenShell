// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const repo = path.resolve(__dirname, '../..');
const dispatcherPath = path.join(repo, '.github/workflows/pr-ci-dispatch.yml');
const publisherPath = path.join(repo, '.github/workflows/required-ci-gates.yml');

const extractScript = (workflowPath, index = 0) => {
  const lines = fs.readFileSync(workflowPath, 'utf8').split('\n');
  const starts = lines.flatMap((line, lineIndex) => (
    line === '          script: |' ? [lineIndex + 1] : []
  ));
  assert.ok(starts[index], `script ${index} missing from ${workflowPath}`);
  const body = [];
  for (let lineIndex = starts[index]; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    if (line && !line.startsWith('            ')) break;
    body.push(line.slice(12));
  }
  return body.join('\n');
};

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const dispatchRoute = new AsyncFunction(
  'github',
  'context',
  'core',
  extractScript(dispatcherPath),
);
const publishRoute = new AsyncFunction(
  'github',
  'context',
  'core',
  extractScript(publisherPath),
);
const dispatchController = new AsyncFunction(
  'github',
  'context',
  'core',
  extractScript(dispatcherPath, 1),
);

const sha = 'a'.repeat(40);
const groupSha = 'b'.repeat(40);
const repository = { owner: 'NVIDIA', repo: 'OpenShell' };

const makePull = (number, labels = []) => ({
  number,
  state: 'open',
  draft: false,
  base: {
    ref: 'main',
    sha: groupSha,
    repo: { full_name: 'NVIDIA/OpenShell' },
  },
  head: {
    sha,
    repo: { full_name: 'NVIDIA/OpenShell' },
  },
  labels: labels.map((name) => ({ name })),
  html_url: `https://github.com/NVIDIA/OpenShell/pull/${number}`,
});

const runDispatchController = async ({
  eventPull,
  openPulls,
  commentsByPull = new Map(),
  initialStatuses = [],
  pullListError = null,
  commentError = null,
}) => {
  const statuses = [...initialStatuses];
  const writes = [];
  const dispatches = [];
  const failures = [];
  let nextRunId = 1000;
  const listPulls = async () => {
    if (pullListError) throw pullListError;
    return openPulls;
  };
  const listComments = async ({ issue_number: issueNumber }) => {
    if (commentError) throw commentError;
    return commentsByPull.get(issueNumber) || [];
  };
  const listStatuses = async () => statuses;
  const github = {
    paginate: async (method, args) => method(args),
    request: async (_route, args) => {
      const id = nextRunId;
      nextRunId += 1;
      dispatches.push(args);
      return {
        data: {
          workflow_run_id: id,
          html_url: `https://github.com/NVIDIA/OpenShell/actions/runs/${id}`,
        },
      };
    },
    rest: {
      actions: {},
      git: {},
      issues: { listComments },
      pulls: {
        get: async () => ({ data: eventPull }),
        list: listPulls,
      },
      repos: {
        createCommitStatus: async (args) => {
          const status = {
            context: args.context,
            state: args.state,
            description: args.description,
            target_url: args.target_url,
          };
          writes.push(status);
          statuses.unshift(status);
          return { data: status };
        },
        getCollaboratorPermissionLevel: async () => ({
          data: { permission: 'write' },
        }),
        listCommitStatusesForRef: listStatuses,
      },
    },
  };
  const context = {
    apiUrl: 'https://api.github.com',
    eventName: 'pull_request_target',
    payload: {
      action: 'opened',
      pull_request: { number: eventPull.number },
      repository: { default_branch: 'main' },
    },
    repo: repository,
    serverUrl: 'https://github.com',
  };
  const core = {
    info: () => {},
    notice: () => {},
    warning: () => {},
    setFailed: (message) => failures.push(message),
  };
  const previousPullNumber = process.env.ROUTED_PULL_NUMBER;
  const previousHeadSha = process.env.ROUTED_HEAD_SHA;
  const originalSetTimeout = global.setTimeout;
  process.env.ROUTED_PULL_NUMBER = String(eventPull.number);
  process.env.ROUTED_HEAD_SHA = eventPull.head.sha;
  global.setTimeout = (callback) => {
    callback();
    return 0;
  };
  try {
    await dispatchController(github, context, core);
  } finally {
    global.setTimeout = originalSetTimeout;
    if (previousPullNumber === undefined) delete process.env.ROUTED_PULL_NUMBER;
    else process.env.ROUTED_PULL_NUMBER = previousPullNumber;
    if (previousHeadSha === undefined) delete process.env.ROUTED_HEAD_SHA;
    else process.env.ROUTED_HEAD_SHA = previousHeadSha;
  }
  return { dispatches, failures, statuses, writes };
};

const routeDispatcher = async (eventName, pullNumber = 42) => {
  const outputs = {};
  await dispatchRoute(
    {
      rest: {
        pulls: {
          get: async () => ({ data: { number: pullNumber, head: { sha } } }),
        },
      },
    },
    {
      eventName,
      repo: repository,
      runId: 900,
      payload: eventName === 'pull_request_target'
        ? { action: 'synchronize', pull_request: { number: pullNumber } }
        : eventName === 'issue_comment'
          ? { issue: { number: pullNumber } }
          : {},
    },
    { setOutput: (name, value) => { outputs[name] = value; } },
  );
  return outputs['lock-key'];
};

const routePublisher = async ({ name, file, workflowId, title }) => {
  const run = {
    id: 100,
    workflow_id: workflowId,
    name,
    path: `.github/workflows/${file}`,
    event: 'workflow_dispatch',
    head_branch: 'main',
    head_repository: { full_name: 'NVIDIA/OpenShell' },
    status: 'completed',
    display_title: title,
  };
  const outputs = {};
  await publishRoute(
    {
      rest: {
        actions: {
          getWorkflowRun: async () => ({ data: run }),
          getWorkflow: async () => ({ data: { id: workflowId } }),
        },
      },
    },
    {
      repo: repository,
      payload: {
        repository: { default_branch: 'main' },
        workflow_run: run,
      },
    },
    { setOutput: (key, value) => { outputs[key] = value; } },
  );
  return outputs['lock-key'];
};

(async () => {
  const prLock = `sha-${sha}`;
  assert.equal(await routeDispatcher('pull_request_target'), prLock);
  assert.equal(await routeDispatcher('issue_comment'), prLock);
  assert.equal(await routeDispatcher('pull_request_target', 43), prLock);
  for (const workflow of [
    ['Branch Checks', 'branch-checks.yml', 701],
    ['Branch E2E Checks', 'branch-e2e.yml', 702],
    ['Helm Lint', 'helm-lint.yml', 703],
  ]) {
    const [name, file, workflowId] = workflow;
    const suffix = name === 'Branch E2E Checks'
      ? ' / core true / gpu false / kubernetes false'
      : '';
    assert.equal(await routePublisher({
      name,
      file,
      workflowId,
      title: `${name} / PR #42 / ${sha} / approval 11${suffix}`,
    }), prLock);
    assert.equal(await routePublisher({
      name,
      file,
      workflowId,
      title: `${name} / PR #43 / ${sha} / approval 12${suffix}`,
    }), prLock);
  }

  assert.equal(await routeDispatcher('schedule'), 'merge-queue');
  for (const workflow of [
    ['Branch Checks', 'branch-checks.yml', 701],
    ['Helm Lint', 'helm-lint.yml', 703],
  ]) {
    const [name, file, workflowId] = workflow;
    assert.equal(await routePublisher({
      name,
      file,
      workflowId,
      title: `${name} / merge group / PR #42 / ${groupSha} / head ${sha} / approval 11`,
    }), 'merge-queue');
  }

  for (const workflowPath of [dispatcherPath, publisherPath]) {
    const text = fs.readFileSync(workflowPath, 'utf8');
    assert.match(text, /group: pr-ci-status-\$\{\{ needs\.route\.outputs\.lock-key \}\}/);
    assert.match(text, /cancel-in-progress: false/);
    assert.match(text, /queue: max/);
  }

  const approvedPull = makePull(42);
  const duplicatePull = makePull(43, ['test:e2e']);
  const approval = {
    id: 11,
    issue_url: 'https://api.github.com/repos/NVIDIA/OpenShell/issues/42',
    body: `/ok to test ${sha}`,
    author_association: 'MEMBER',
    user: { login: 'maintainer' },
  };
  const aggregate = await runDispatchController({
    eventPull: duplicatePull,
    openPulls: [duplicatePull, approvedPull],
    commentsByPull: new Map([[42, [approval]]]),
  });
  assert.deepEqual(aggregate.failures, []);
  assert.equal(aggregate.dispatches.length, 3);
  assert.ok(aggregate.dispatches.every((run) => run.inputs.pr_number === '42'));
  const e2eDispatch = aggregate.dispatches.find(
    (run) => run.workflow_id === 'branch-e2e.yml',
  );
  assert.equal(e2eDispatch.inputs.run_core_e2e, 'true');
  assert.equal(e2eDispatch.inputs.run_gpu_e2e, 'false');
  assert.equal(e2eDispatch.inputs.run_kubernetes_e2e, 'false');
  const aggregateStatuses = new Map(
    aggregate.statuses.map((status) => [status.context, status]),
  );
  assert.equal(aggregateStatuses.get('OpenShell / E2E').state, 'pending');
  assert.equal(aggregateStatuses.get('OpenShell / GPU E2E').state, 'success');

  const currentRunUrl = 'https://github.com/NVIDIA/OpenShell/actions/runs/777';
  const unresolved = await runDispatchController({
    eventPull: approvedPull,
    openPulls: [approvedPull],
    initialStatuses: [{
      context: 'OpenShell / E2E',
      state: 'pending',
      description: 'Branch E2E dispatched for approved SHA',
      target_url: currentRunUrl,
    }],
    pullListError: new Error('temporary API failure'),
  });
  assert.equal(unresolved.failures.length, 1);
  assert.deepEqual(unresolved.dispatches, []);
  assert.deepEqual(unresolved.writes, []);
  assert.equal(unresolved.statuses[0].target_url, currentRunUrl);

  console.log('PR status aggregation and lossless serialization checks passed.');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
