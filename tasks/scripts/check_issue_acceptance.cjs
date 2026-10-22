// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

module.exports = async function checkIssueAcceptance({ github, context, core }) {
  const { owner, repo } = context.repo;
  const { data: pr } = await github.rest.pulls.get({
    owner, repo, pull_number: context.payload.pull_request.number,
  });
  const author = pr.user.login;

  async function evaluate() {
    try {
      const { data } = await github.rest.repos.getCollaboratorPermissionLevel({
        owner, repo, username: author,
      });
      // The REST API maps maintain to write and triage to read.
      if (['write', 'maintain', 'admin'].includes(data.permission)) {
        core.info(`${author} has repository write access; acceptance gate passed.`);
        return;
      }
    } catch (error) {
      if (error.status !== 404) throw error;
    }

    const issues = [];
    let cursor = null;
    do {
      const result = await github.graphql(`
        query($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
          repository(owner: $owner, name: $repo) {
            pullRequest(number: $number) {
              closingIssuesReferences(first: 100, after: $cursor) {
                nodes { number url repository { name owner { login } } }
                pageInfo { hasNextPage endCursor }
              }
            }
          }
        }
      `, { owner, repo, number: pr.number, cursor });
      const linked = result.repository.pullRequest.closingIssuesReferences;
      issues.push(...linked.nodes);
      cursor = linked.pageInfo.hasNextPage ? linked.pageInfo.endCursor : null;
    } while (cursor);

    if (issues.length === 0) {
      return 'Community PRs must link an issue with state:accepted using '
        + 'Fixes #NNN or Closes #NNN.';
    }

    const unaccepted = [];
    for (const issue of issues) {
      if (`${issue.repository.owner.login}/${issue.repository.name}`.toLowerCase()
        !== `${owner}/${repo}`.toLowerCase()) {
        return `Acceptance must be recorded in ${owner}/${repo}, not ${issue.url}.`;
      }
      const labels = await github.paginate(github.rest.issues.listLabelsOnIssue, {
        owner: issue.repository.owner.login,
        repo: issue.repository.name,
        issue_number: issue.number,
        per_page: 100,
      });
      if (!labels.some(label => label.name === 'state:accepted')) {
        unaccepted.push(issue.url);
      }
    }

    if (unaccepted.length) {
      return 'Community PRs require state:accepted on every linked issue. '
        + `Ask a maintainer to accept: ${unaccepted.join(', ')}. `
        + 'After acceptance, rerun this workflow.';
    }
    core.info(`All ${issues.length} linked issue(s) have state:accepted.`);
  }

  const failure = await evaluate();
  if (failure) core.setFailed(failure);
};
