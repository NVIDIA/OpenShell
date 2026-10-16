# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
PR_WORKFLOWS = (
    ".github/workflows/branch-checks.yml",
    ".github/workflows/branch-e2e.yml",
    ".github/workflows/helm-lint.yml",
    ".github/workflows/windows-msvc.yml",
)

PR_REUSABLE_WORKFLOWS = (
    ".github/workflows/build-binaries.yml",
    ".github/workflows/build-images.yml",
    ".github/workflows/build-rpm.yml",
    ".github/workflows/build-vm-driver.yml",
    ".github/workflows/codex-compatibility.yml",
    ".github/workflows/deb-package.yml",
    ".github/workflows/e2e-docker-test.yml",
    ".github/workflows/e2e-gpu-test.yaml",
    ".github/workflows/e2e-kubernetes-test.yml",
    ".github/workflows/e2e-podman-test.yml",
    ".github/workflows/e2e-vm-test.yml",
    ".github/workflows/integration-runner.yml",
    ".github/workflows/prepare-integration-inputs.yml",
    ".github/workflows/rpm-package.yml",
)


class WorkflowLoader(yaml.SafeLoader):
    """Parse GitHub's YAML 1.2-style `on` key without YAML 1.1 booleans."""


WorkflowLoader.yaml_implicit_resolvers = {
    key: [
        (tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def load_workflow(relative_path: str) -> dict[str, Any]:
    parsed = yaml.load(read(relative_path), Loader=WorkflowLoader)
    assert isinstance(parsed, dict)
    return parsed


def workflow_inputs(workflow: dict[str, Any]) -> dict[str, Any]:
    triggers = workflow.get("on", {})
    assert isinstance(triggers, dict)
    dispatch = triggers.get("workflow_dispatch", {})
    assert isinstance(dispatch, dict)
    inputs = dispatch.get("inputs", {})
    assert isinstance(inputs, dict)
    return inputs


def iter_step_uses(workflow: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for job in workflow.get("jobs", {}).values():
        for step in job.get("steps", []):
            if "uses" in step:
                values.append(str(step["uses"]))
    return values


def test_mirror_bot_is_disabled_and_mirror_triggers_are_gone() -> None:
    assert yaml.safe_load(read(".github/copy-pr-bot.yaml"))["enabled"] is False

    for path in sorted((REPO_ROOT / ".github/workflows").glob("*.y*ml")):
        relative = str(path.relative_to(REPO_ROOT))
        assert "pull-request/" not in read(relative), relative

    assert not (REPO_ROOT / ".github/actions/pr-gate/action.yml").exists()
    assert not (REPO_ROOT / ".github/actions/pr-merge-base/action.yml").exists()


def test_dispatcher_validates_and_dispatches_the_exact_approved_sha() -> None:
    workflow = load_workflow(".github/workflows/pr-ci-dispatch.yml")
    text = read(".github/workflows/pr-ci-dispatch.yml")

    assert workflow["on"]["issue_comment"]["types"] == ["created"]
    assert {
        "opened",
        "synchronize",
        "labeled",
        "unlabeled",
        "ready_for_review",
        "reopened",
    } <= set(workflow["on"]["pull_request_target"]["types"])
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["dispatch"]["permissions"] == {
        "actions": "write",
        "contents": "read",
        "issues": "read",
        "pull-requests": "read",
        "statuses": "write",
    }
    assert all(
        not use.startswith("actions/checkout@") for use in iter_step_uses(workflow)
    )
    assert all(not use.startswith(("./", "$/")) for use in iter_step_uses(workflow))

    assert "Bind status serialization to the current revision" in text
    assert "`sha-${pull.head.sha}`" in text
    assert "pr-ci-status-${{ needs.route.outputs.lock-key }}" in text
    assert "eventPull.head.sha !== process.env.ROUTED_HEAD_SHA" in text
    assert "status.state === 'pending' && run.status === 'completed'" in text
    assert "format('ignored-{0}', github.run_id)" in text
    assert "format('pr-{0}', github.event.issue.number)" in text
    assert "format('pr-{0}', github.event.pull_request.number)" in text
    route_job = workflow["jobs"]["route"]
    dispatch_job = workflow["jobs"]["dispatch"]
    assert route_job["permissions"] == {"pull-requests": "read"}
    assert dispatch_job["needs"] == "route"
    assert "pr-ci-status-" in dispatch_job["concurrency"]["group"]
    assert dispatch_job["concurrency"]["cancel-in-progress"] == "false"
    assert dispatch_job["concurrency"]["queue"] == "max"
    assert "startsWith(github.event.comment.body, '/ok to test ')" in text
    for association in ("OWNER", "MEMBER", "COLLABORATOR"):
        assert f"github.event.comment.author_association == '{association}'" in text
    assert "const permissionCache = new Map()" in text
    assert "const statusCache = new Map()" in text
    assert "permissionCache.has(login)" in text
    assert "maintainerAssociations.has(authorAssociation)" in text
    assert "current?.state === state" in text
    assert "const command = `/ok to test ${eventPull.head.sha}`" in text
    assert "String(comment.body || '').trim() === command" in text
    assert "getCollaboratorPermissionLevel" in text
    assert "['admin', 'maintain', 'write']" in text
    assert "github.paginate" in text
    assert "approval_comment_id" in text
    assert "ref: defaultBranch" in text
    assert "X-GitHub-Api-Version" in text
    assert "return_run_details" not in text
    assert "workflow_run_id" in text
    assert "response.data?.html_url" in text
    assert "isE2eLabelEvent" not in text
    assert "trustedRunStillOwnsStatus" in text
    assert "trustedWorkflowRunExists" in text
    assert "github.paginate(github.rest.issues.listComments" in text
    for marker in (
        "pull.head?.repo?.full_name",
        "compareCommitsWithBasehead",
        "workflowTreeIdentity",
        "github.rest.git.getCommit",
        "github.rest.git.getTree",
        "tree.truncated",
        "matches.length !== 1",
        "matches[0].type !== 'tree'",
        "matches[0].mode !== '040000'",
        "baseWorkflowTree !== headWorkflowTree",
    ):
        assert marker in text
    assert "github.rest.pulls.listFiles" not in text
    for target in (
        "branch-checks.yml",
        "branch-e2e.yml",
        "helm-lint.yml",
        "windows-msvc.yml",
    ):
        assert target in text

    required_gates = load_workflow(".github/workflows/required-ci-gates.yml")
    assert set(required_gates["on"]) == {"workflow_run"}


def test_merge_queue_is_dispatched_only_from_the_trusted_default_branch() -> None:
    for path in sorted((REPO_ROOT / ".github/workflows").glob("*.y*ml")):
        relative = str(path.relative_to(REPO_ROOT))
        triggers = load_workflow(relative).get("on", {})
        assert not isinstance(triggers, dict) or "merge_group" not in triggers, relative

    workflow = load_workflow(".github/workflows/pr-ci-dispatch.yml")
    text = read(".github/workflows/pr-ci-dispatch.yml")
    triggers = workflow["on"]

    assert {"enqueued", "dequeued"} <= set(triggers["pull_request_target"]["types"])
    assert isinstance(triggers["schedule"], list)
    assert triggers["schedule"]
    assert all(item.get("cron") for item in triggers["schedule"])

    # The trusted dispatcher discovers active entries from GitHub's merge
    # queue and verifies their synthesized refs before dispatching checks.
    for marker in (
        "github.graphql",
        "mergeQueue(branch:",
        "entries",
        "baseCommit",
        "headCommit",
        "pullRequest",
        "github.rest.git.getRef",
        "heads/gh-readonly-queue/",
        "queueRefData.object?.type !== 'commit'",
        "queueRefData.object.sha !== groupSha",
    ):
        assert marker in text

    assert "ref: defaultBranch" in text
    assert "merge_group_sha: groupSha" in text
    assert "branch-checks.yml" in text
    assert "helm-lint.yml" in text


def test_merge_queue_sha_is_revalidated_before_candidate_checkout() -> None:
    action_path = ".github/actions/authorize-pr-ci/action.yml"
    action = yaml.safe_load(read(action_path))
    action_text = read(action_path)

    assert "merge-group-sha" in action["inputs"]
    for marker in (
        "github.graphql",
        "isInMergeQueue",
        "mergeQueueEntry",
        "baseCommit",
        "headCommit",
        "pullRequest",
        "github.rest.git.getRef",
        "heads/gh-readonly-queue/",
        "queuedHead !== mergeGroupSha",
        "queueRefData.object.sha !== mergeGroupSha",
    ):
        assert marker in action_text

    for relative in (
        ".github/workflows/branch-checks.yml",
        ".github/workflows/helm-lint.yml",
    ):
        workflow = load_workflow(relative)
        text = read(relative)
        inputs = workflow_inputs(workflow)

        assert "merge_group_sha" in inputs, relative
        assert "merge-group-sha: ${{ inputs.merge_group_sha }}" in text, relative
        assert "uses: $/.github/actions/authorize-pr-ci" in text, relative


def test_dispatched_candidate_workflows_reauthorize_before_checkout() -> None:
    for relative in PR_WORKFLOWS:
        workflow = load_workflow(relative)
        text = read(relative)
        inputs = workflow_inputs(workflow)

        assert {"pr_number", "head_sha", "approval_comment_id"} <= set(inputs), relative
        assert "packages: write" not in text, relative
        assert "CACHIX_AUTH_TOKEN" not in text, relative
        assert "pull-request/" not in text, relative
        assert "uses: $/.github/actions/authorize-pr-ci" in text, relative
        assert "approval-comment-id: ${{ inputs.approval_comment_id }}" in text, (
            relative
        )
        assert (
            "repository: ${{ needs.pr_metadata.outputs.checkout_repository }}" in text
        ), relative
        assert (
            "ref: ${{ needs.pr_metadata.outputs.head_sha }}" in text
            or "ref: ${{ needs.pr_metadata.outputs.checkout_ref }}" in text
        ), relative

        # Composite actions in a candidate job must resolve from the trusted
        # workflow revision, even after the candidate checkout replaces the
        # workspace. Job-level reusable workflows are resolved by GitHub before
        # a runner starts and are intentionally outside this check.
        for use in iter_step_uses(workflow):
            assert not use.startswith("./.github/actions/"), (relative, use)

    for relative in PR_REUSABLE_WORKFLOWS:
        workflow = load_workflow(relative)
        for use in iter_step_uses(workflow):
            assert not use.startswith("./.github/actions/"), (relative, use)
        for job in workflow.get("jobs", {}).values():
            use = str(job.get("uses", ""))
            assert not use.startswith("./.github/workflows/"), (relative, use)

    for action_path in sorted((REPO_ROOT / ".github/actions").glob("*/action.yml")):
        action = yaml.safe_load(action_path.read_text(encoding="utf-8"))
        for step in action.get("runs", {}).get("steps", []):
            use = str(step.get("uses", ""))
            assert not use.startswith("./.github/actions/"), (action_path, use)

    for relative in PR_WORKFLOWS[:3]:
        assert load_workflow(relative)["cache-mode"] == "read", relative
    windows = load_workflow(".github/workflows/windows-msvc.yml")
    assert windows["jobs"]["pr-check"]["cache-mode"] == "read"


def test_authorizer_binds_dispatch_to_current_pr_and_approval() -> None:
    action = read(".github/actions/authorize-pr-ci/action.yml")

    for marker in (
        "pull.state !== 'open'",
        "pull.draft",
        "pull.base.repo.full_name !== repoName",
        "pull.base.ref !== context.payload.repository.default_branch",
        "pull.head.sha !== requestedSha",
        "issues.getComment",
        "comment.issue_url !== expectedIssueUrl",
        "String(comment.body || '').trim() !== `/ok to test ${requestedSha}`",
        "getCollaboratorPermissionLevel",
        "['admin', 'maintain', 'write']",
        "compareCommitsWithBasehead",
        "pull.head.repo.full_name",
        "workflowTreeIdentity",
        "github.rest.git.getCommit",
        "github.rest.git.getTree",
        "tree.truncated",
        "matches.length !== 1",
        "matches[0].type !== 'tree'",
        "matches[0].mode !== '040000'",
        "baseWorkflowTree !== headWorkflowTree",
    ):
        assert marker in action
    assert "github.rest.pulls.listFiles" not in action

    parsed_action = yaml.safe_load(action)
    assert "merge-base-sha" in parsed_action["outputs"]
    assert "core.setOutput('base-sha', pull.base.sha)" in action
    assert "core.setOutput('merge-base-sha', mergeBaseSha)" in action

    helm = read(".github/workflows/helm-lint.yml")
    assert "merge_base_sha: ${{ steps.authorize.outputs.merge-base-sha }}" in helm
    assert "BASE_SHA: ${{ needs.pr_metadata.outputs.merge_base_sha }}" in helm
    assert "base_sha: ${{ needs.pr_metadata.outputs.merge_base_sha }}" in helm

    branch = read(".github/workflows/branch-checks.yml")
    assert "BASE_SHA: ${{ needs.pr_metadata.outputs.base_sha }}" in branch
    assert '"$BASE_REPOSITORY_URL" "$BASE_SHA"' in branch

    compatibility = read(".github/workflows/codex-compatibility.yml")
    assert '"${{ github.server_url }}/${BASE_REPOSITORY}.git" "$BASE_REF"' in (
        compatibility
    )


def test_compatibility_secret_is_isolated_from_candidate_code() -> None:
    branch = load_workflow(".github/workflows/branch-checks.yml")
    compatibility = load_workflow(".github/workflows/codex-compatibility.yml")
    compatibility_text = read(".github/workflows/codex-compatibility.yml")
    reviewer = read("tasks/scripts/codex_compatibility.py")

    caller = branch["jobs"]["compatibility-review"]
    assert caller["uses"] == "$/.github/workflows/codex-compatibility.yml"
    assert caller["permissions"] == {"contents": "read", "pull-requests": "read"}
    assert caller["secrets"] == {
        "CODEX_SECURITY_API_KEY": "${{ secrets.CODEX_SECURITY_API_KEY }}"
    }
    assert compatibility["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
    }

    review_steps = compatibility["jobs"]["review"]["steps"]
    tooling_checkout = next(
        step
        for step in review_steps
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert tooling_checkout["with"] == {
        "ref": "${{ github.workflow_sha }}",
        "path": "review-tools",
        "fetch-depth": 0,
        "persist-credentials": "false",
    }
    assert "git -c core.hooksPath=/dev/null fetch --no-tags" in compatibility_text
    assert "working-directory: review-tools" in compatibility_text
    assert (
        "actions/checkout"
        not in compatibility_text.split(
            "- name: Fetch exact branch comparison commits", maxsplit=1
        )[1]
    )

    assert 'permissions.compatibility.extends=":read-only"' in reviewer
    assert 'permissions.compatibility.network.domains={"api.github.com"="allow"}' in (
        reviewer
    )
    assert "permissions.compatibility.network.allow_upstream_proxy=false" in reviewer
    assert "permissions.compatibility.network.enable_socks5=false" in reviewer
    assert "project_doc_max_bytes=0" in reviewer
    assert "features.hooks=false" in reviewer
    assert "features.plugins=false" in reviewer
    assert "features.multi_agent=false" in reviewer
    assert (
        'shell_environment_policy.filters={PATH="include", HOME="include", GH_TOKEN="include"'
        in (reviewer)
    )
    filter_tail = reviewer.split("shell_environment_policy.filters=", maxsplit=1)[1]
    filter_tail = filter_tail.split("',", maxsplit=1)[0]
    assert "NVIDIA_INFERENCE_API_KEY" not in filter_tail
    assert '"git",\n            "clone",\n            "--bare"' in reviewer


def test_non_pr_authorization_is_limited_to_the_windows_branch() -> None:
    action = read(".github/actions/authorize-pr-ci/action.yml")
    windows = read(".github/workflows/windows-msvc.yml")

    assert "trusted-ref" in action
    assert "trustedRef === 'refs/heads/windows'" in action
    assert "workflowRef === trustedRef" in action
    assert "['push', 'workflow_dispatch'].includes(eventName)" in action
    assert "if (!prNumberText && trustedRef)" in action
    assert "trusted-ref: ${{ inputs.pr_number == ''" in windows
    assert "github.ref == 'refs/heads/windows'" in windows


def test_required_gate_accepts_only_the_pointered_authorized_run() -> None:
    workflow = load_workflow(".github/workflows/required-ci-gates.yml")
    text = read(".github/workflows/required-ci-gates.yml")
    e2e_text = read(".github/workflows/branch-e2e.yml")

    assert "workflow_run" in workflow["on"]
    assert set(workflow["on"]["workflow_run"]["workflows"]) == {
        "Branch Checks",
        "Branch E2E Checks",
        "Helm Lint",
    }
    assert "pull-request/" not in text
    route = workflow["jobs"]["route"]
    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == "route"
    assert publish["if"] == "needs.route.outputs.lock-key != ''"
    assert publish["concurrency"] == {
        "group": "pr-ci-status-${{ needs.route.outputs.lock-key }}",
        "cancel-in-progress": "false",
        "queue": "max",
    }
    assert all(
        not str(step.get("uses", "")).startswith("actions/checkout@")
        for step in route["steps"]
    )
    for marker in (
        "github.rest.actions.getWorkflowRun",
        "github.rest.actions.getWorkflow",
        "run.workflow_id !== trustedWorkflow.id",
        "run.event !== 'workflow_dispatch'",
        "run.head_repository?.full_name !== expectedRepository",
        "definition.kind === 'e2e'",
        "core.setOutput('lock-key', 'merge-queue')",
        "`sha-${pullMatch[2]}`",
        "runIdFromTargetUrl",
        "pointedRun.workflow_id === payloadRun.workflow_id",
        "Reconciling current run",
    ):
        assert marker in text
    for marker in (
        "workflow_dispatch",
        "display_title",
        "approval",
        "html_url",
        "target_url",
        "run_attempt",
        "approvalCommentId",
        "/ok to test",
        "getCollaboratorPermissionLevel",
        "Authorize PR revision",
        "filter: 'latest'",
        "normalizeWorkflowPath",
        "split('@', 1)",
    ):
        assert marker in text
    assert "workflow.kind === 'e2e'" in text
    assert "/ core (true|false) / gpu (true|false) /" in text
    assert "kubernetes (true|false)$" in text
    assert "approval {2} / core {3} / gpu {4} / kubernetes {5}" in e2e_text
    for input_name in (
        "inputs.run_core_e2e",
        "inputs.run_gpu_e2e",
        "inputs.run_kubernetes_e2e",
    ):
        assert input_name in e2e_text
    assert "run.event !== 'workflow_dispatch'" in text
    assert "run.head_branch !== repository.default_branch" in text
    assert "listCommitStatusesForRef" in text
    assert "target_url === run.html_url" in text
    assert "github.paginate" in text
    assert "pull.head.sha === approvedHeadSha" in text
    assert "comment.issue_url === expectedIssueUrl" in text
    assert "isMergeQueueRun && !pullIsCurrent" in text
    for marker in (
        "github.rest.pulls.list",
        "base: defaultBranch",
        "candidate.base?.repo?.full_name === expectedRepository",
        "candidate.base?.ref === defaultBranch",
        "candidate.head?.sha === eventPull.head.sha",
        "matchingPulls.flatMap",
        "(candidate.labels || []).map((label) => label.name)",
        "comment.issue_url === expectedIssueUrl",
        "const approved = approvalCommentId !== 0",
        "blockRequiredTests(",
        "currentStatuses.get(statusContext)?.state === 'pending'",
        "Preserving the current pending",
        "Waiting to resolve current PR requirements",
        "Waiting to bind this PR to its candidate SHA",
        "Waiting to resolve exact-SHA approval",
    ):
        assert marker in read(".github/workflows/pr-ci-dispatch.yml")
    for marker in (
        "base: repository.default_branch",
        "const requiredLabels = new Set",
        "'test:e2e': pullTitleMatch?.[4] === 'true'",
        "'test:e2e-gpu': pullTitleMatch?.[5] === 'true'",
        "'test:e2e-kubernetes': pullTitleMatch?.[6] === 'true'",
        "E2E selection no longer covers",
        "targetUrl = run.html_url",
        "`E2E selection no longer covers ${missingSelection[0]}`",
        "core.setFailed(`Could not resolve current E2E requirements",
        "const statusLabels = new Map",
        "const requiredContexts = new Set()",
        "`${label} not applied`",
        "pull.html_url",
    ):
        assert marker in text
    for marker in (
        "mergeQueueEntry",
        "entry.headCommit?.oid === candidateSha",
        "entryPull.headRefOid === approvedHeadSha",
        "github.rest.git.getRef",
        "heads/gh-readonly-queue/",
        "queueRefData.object.sha !== candidateSha",
    ):
        assert marker in text


def test_status_writers_share_lossless_serialization_keys() -> None:
    subprocess.run(
        ["node", "tasks/scripts/check_pr_ci_status_serialization_test.cjs"],
        cwd=REPO_ROOT,
        check=True,
    )


def test_release_canary_accepts_only_trusted_release_dev_runs() -> None:
    workflow = load_workflow(".github/workflows/release-canary.yml")
    text = read(".github/workflows/release-canary.yml")
    authorize = workflow["jobs"]["authorize"]

    assert workflow["permissions"] == {"actions": "read", "contents": "read"}
    assert any(
        str(step.get("uses", "")).startswith("actions/github-script@")
        for step in authorize["steps"]
    )
    assert all(
        not str(step.get("uses", "")).startswith("actions/checkout@")
        for step in authorize["steps"]
    )
    for marker in (
        "github.rest.actions.getWorkflowRun",
        "github.rest.actions.getWorkflow",
        "workflow_id: 'release-dev.yml'",
        "run.workflow_id !== trustedWorkflow.id",
        "run.name !== 'Release Dev'",
        "workflowPath !== '.github/workflows/release-dev.yml'",
        "run.event === 'push' && run.head_branch === defaultBranch",
        "run.event === 'workflow_dispatch' && run.actor?.login",
        "run.repository?.full_name !== expectedRepository",
        "run.head_repository?.full_name !== expectedRepository",
        "github.rest.git.getCommit",
        "github.rest.repos.getCollaboratorPermissionLevel",
        "['admin', 'maintain', 'write']",
        "github.rest.git.getRef",
        "comparison.data.merge_base_commit?.sha !== run.head_sha",
        "core.setOutput('candidate-sha', run.head_sha)",
    ):
        assert marker in text

    assert "github.event.workflow_run.head_sha || github.sha" not in text
    for job_name, job in workflow["jobs"].items():
        if job_name == "authorize":
            continue
        assert job["needs"] == "authorize", job_name
        assert job["if"] == "needs.authorize.outputs.candidate_sha != ''", job_name
    assert text.count("needs.authorize.outputs.candidate_sha }}/install.sh") == 6


def test_pr_images_are_artifacts_only_and_release_publish_is_explicit() -> None:
    branch = read(".github/workflows/branch-e2e.yml")
    branch_workflow = load_workflow(".github/workflows/branch-e2e.yml")
    build_workflow = load_workflow(".github/workflows/build-images.yml")
    build_action = read(".github/actions/build-docker-image/action.yml")
    loader = read(".github/actions/load-image-artifacts/action.yml")

    push_input = build_workflow["on"]["workflow_call"]["inputs"]["push-images"]
    assert push_input["default"] == "false"
    assert "permissions" not in build_workflow
    assert "push-images: false" in branch
    assert "packages: write" not in branch
    branch_jobs = branch_workflow["jobs"]
    assert branch_jobs["build-images"]["permissions"] == {
        "actions": "read",
        "contents": "read",
    }
    assert branch_jobs["build-images"]["with"]["push-images"] == "false"
    artifact_consumers = (
        "prepare-integration",
        "docker-e2e",
        "podman-e2e",
        "docker-external-driver-e2e",
        "podman-external-driver-e2e",
        "gpu-e2e",
        "kubernetes-e2e",
        "kubernetes-workspace-managed-e2e",
        "kubernetes-external-driver-e2e",
        "kubernetes-workspace-operator-e2e",
        "kubernetes-ha-e2e",
        "kubernetes-credential-drivers-e2e",
    )
    for job_name in artifact_consumers:
        assert branch_jobs[job_name]["with"]["use-image-artifacts"] == "true"
    assert 'default: "false"' in build_action
    assert "for arch in amd64 arm64" in build_action
    assert (
        "type=docker,dest=artifacts/images/${COMPONENT}-linux-${arch}.tar"
        in build_action
    )
    assert "--cache-to" not in build_action.split("exit 0", maxsplit=1)[1]
    assert "${component}-linux-${arch}.tar" in loader
    assert '"$ENGINE" image inspect' in loader

    for release in ("release-dev.yml", "release-build.yml"):
        release_workflow = load_workflow(f".github/workflows/{release}")
        image_job = release_workflow["jobs"]["build-images"]
        assert image_job["with"]["push-images"] == "true", release
        assert image_job["permissions"] == {
            "contents": "read",
            "packages": "write",
        }, release


def test_manual_integration_uses_the_exact_candidate_artifact_run() -> None:
    manual = load_workflow(".github/workflows/integration-test.yml")
    prepare = load_workflow(".github/workflows/prepare-integration-inputs.yml")
    runner = load_workflow(".github/workflows/integration-runner.yml")
    loader = yaml.safe_load(read(".github/actions/load-image-artifacts/action.yml"))

    manual_inputs = workflow_inputs(manual)
    assert manual_inputs["artifact-run-id"]["required"] == "true"
    assert manual_inputs["source-sha"]["required"] == "true"
    assert "checkout-repository" in manual_inputs
    assert manual_inputs["use-image-artifacts"]["default"] == "true"
    assert manual["permissions"] == {
        "actions": "read",
        "contents": "read",
        "packages": "read",
    }
    assert manual["cache-mode"] == "read"
    assert prepare["permissions"] == {
        "actions": "read",
        "contents": "read",
        "packages": "read",
    }

    manual_prepare = manual["jobs"]["prepare"]["with"]
    assert manual_prepare["artifact-run-id"] == "${{ inputs['artifact-run-id'] }}"
    assert manual_prepare["source-sha"] == "${{ inputs['source-sha'] }}"
    assert manual_prepare["checkout-repository"] == (
        "${{ inputs['checkout-repository'] }}"
    )
    assert manual_prepare["use-image-artifacts"] == (
        "${{ inputs['use-image-artifacts'] }}"
    )

    manual_runner = manual["jobs"]["integration"]["with"]
    assert manual_runner["checkout-repository"] == (
        "${{ inputs['checkout-repository'] }}"
    )
    assert runner["concurrency"]["group"] == (
        "${{ github.workflow }}-integration-${{ inputs.category }}-"
        "${{ inputs.source-sha }}"
    )
    assert "github.ref" not in runner["concurrency"]["group"]

    prepare_inputs = workflow_inputs(prepare)
    assert "checkout-ref" not in prepare_inputs
    prepare_steps = prepare["jobs"]["prepare"]["steps"]
    resolve = next(
        step for step in prepare_steps if step.get("name") == "Resolve artifact run"
    )
    assert resolve["env"]["ARTIFACT_RUN_ID_INPUT"] == (
        "${{ inputs['artifact-run-id'] }}"
    )
    assert '[ -n "$ARTIFACT_RUN_ID_INPUT" ] && [ -z "$SOURCE_SHA" ]' in (resolve["run"])
    checkout = next(
        step
        for step in prepare_steps
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"]["ref"] == ("${{ steps.artifact-run.outputs.source_sha }}")
    image_loader = next(
        step
        for step in prepare_steps
        if step.get("uses") == "$/.github/actions/load-image-artifacts"
    )
    assert image_loader["with"]["artifact-run-id"] == (
        "${{ inputs['artifact-run-id'] }}"
    )

    download = loader["runs"]["steps"][0]
    assert loader["inputs"]["artifact-run-id"]["default"] == ""
    assert download["with"]["github-token"] == "${{ github.token }}"
    assert download["with"]["repository"] == "${{ github.repository }}"
    assert download["with"]["run-id"] == (
        "${{ inputs.artifact-run-id || github.run_id }}"
    )


def test_label_help_never_checks_out_candidate_code() -> None:
    workflow = load_workflow(".github/workflows/e2e-label-help.yml")
    text = read(".github/workflows/e2e-label-help.yml")

    assert all(
        not use.startswith("actions/checkout@") for use in iter_step_uses(workflow)
    )
    assert "pull-request/" not in text
    assert "/ok to test $PR_HEAD_SHA" in text


def test_prebuilt_e2e_binaries_use_outputs_without_mutating_job_env(
    tmp_path: Path,
) -> None:
    actions = {
        "cli": ("openshell", "OPENSHELL_BIN"),
        "gateway": ("openshell-gateway", "OPENSHELL_GATEWAY_BIN"),
        "vm-driver": ("openshell-driver-vm", "OPENSHELL_VM_DRIVER_BIN"),
    }
    workspace = tmp_path / "workspace with spaces"
    workspace.mkdir()
    environment_file = tmp_path / "environment"
    environment_file.write_text("PRESERVE_EXISTING=value\n", encoding="utf-8")
    for action, (binary_name, _) in actions.items():
        definition = load_workflow(f".github/actions/setup-e2e-{action}/action.yml")
        output_ref = re.fullmatch(
            r"\$\{\{ steps\.([\w-]+)\.outputs\.([\w-]+) \}\}",
            definition["outputs"]["binary"]["value"],
        )
        assert output_ref is not None
        configure = next(
            step
            for step in definition["runs"]["steps"]
            if step.get("id") == output_ref[1]
        )
        download = next(
            step
            for step in definition["runs"]["steps"]
            if step.get("uses", "").startswith("actions/download-artifact@")
        )
        binary = workspace / download["with"]["path"] / binary_name
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/bin/sh\nprintf 'fixture-version\\n'\n", encoding="utf-8")
        output_file = tmp_path / f"{action}.output"
        output_file.touch()
        subprocess.run(
            ["bash", "-euo", "pipefail", "-c", configure["run"]],
            env={
                **os.environ,
                "GITHUB_WORKSPACE": str(workspace),
                "GITHUB_OUTPUT": str(output_file),
                "GITHUB_ENV": str(environment_file),
            },
            check=True,
            capture_output=True,
        )
        outputs = dict(
            line.split("=", 1) for line in output_file.read_text().splitlines()
        )
        assert outputs[output_ref[2]] == str(binary)
        assert os.access(binary, os.X_OK)
        subprocess.run(
            [outputs[output_ref[2]], "--version"], check=True, capture_output=True
        )
        assert environment_file.read_text() == "PRESERVE_EXISTING=value\n"

    callers = set()
    for relative_path in PR_REUSABLE_WORKFLOWS:
        workflow = load_workflow(relative_path)
        for job in workflow["jobs"].values():
            steps = job.get("steps", [])
            for action, (_, variable) in actions.items():
                for index, step in enumerate(steps):
                    if step.get("uses") != f"$/.github/actions/setup-e2e-{action}":
                        continue
                    callers.add(relative_path)
                    expected = "${{ steps." + step["id"] + ".outputs.binary }}"
                    assert any(
                        consumer.get("env", {}).get(variable) == expected
                        and "run" in consumer
                        for consumer in steps[index + 1 :]
                    ), (relative_path, action)
    assert len(callers) == 5
