# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import importlib.util
import sys
from pathlib import Path
from typing import cast

import pytest

MODULE_PATH = Path(__file__).with_name("github_actions_policy.py")
SPEC = importlib.util.spec_from_file_location("github_actions_policy", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
policy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = policy
SPEC.loader.exec_module(policy)


def test_discover_references_preserves_locations_and_supported_forms() -> None:
    source = """
jobs:
  build:
    uses: owner/reusable/.github/workflows/build.yml@v1
    steps:
      - uses: actions/checkout@0123456789012345678901234567890123456789 # pinned
      - uses: './.github/actions/local'
      - uses: "docker://alpine:3.22"
      - {"uses": owner/inline@sha}
"""

    assert policy.discover_references(source, ".github/workflows/ci.yml") == [
        policy.Reference(
            "owner/reusable/.github/workflows/build.yml@v1",
            ".github/workflows/ci.yml",
            4,
        ),
        policy.Reference(
            "actions/checkout@0123456789012345678901234567890123456789",
            ".github/workflows/ci.yml",
            6,
        ),
        policy.Reference("./.github/actions/local", ".github/workflows/ci.yml", 7),
        policy.Reference("docker://alpine:3.22", ".github/workflows/ci.yml", 8),
        policy.Reference("owner/inline@sha", ".github/workflows/ci.yml", 9),
    ]


@pytest.mark.parametrize(
    "source",
    [
        "jobs:\n  build:\n    steps:\n      - uses: |\n          owner/repo@v1\n",
        "jobs:\n  build:\n    steps:\n      - uses: ${{ matrix.action }}\n",
        "jobs:\n  build:\n    steps:\n      - uses: [owner/repo@v1]\n",
    ],
)
def test_discover_references_rejects_ambiguous_uses_syntax(source: str) -> None:
    with pytest.raises(policy.EvaluationError, match="uses"):
        policy.discover_references(source, ".github/workflows/ci.yml")


def test_discover_references_finds_quoted_uses_key() -> None:
    source = 'jobs:\n  build:\n    steps:\n      - "uses": attacker/action@v1\n'

    assert policy.discover_references(source, ".github/workflows/ci.yml") == [
        policy.Reference("attacker/action@v1", ".github/workflows/ci.yml", 4)
    ]


def test_added_references_compares_occurrence_counts() -> None:
    base = [
        policy.Reference("owner/action@old", "ci.yml", 2),
        policy.Reference("owner/action@same", "ci.yml", 3),
    ]
    head = [
        policy.Reference("owner/action@same", "ci.yml", 4),
        policy.Reference("owner/action@new", "ci.yml", 5),
        policy.Reference("owner/action@new", "ci.yml", 6),
    ]

    assert policy.added_references(base, head) == head[1:]


def test_discover_references_ignores_uses_text_inside_block_scalar() -> None:
    source = """
jobs:
  build:
    steps:
      - run: |
          echo "uses: attacker/action@main"
      - uses: owner/action@sha
"""

    assert policy.discover_references(source, ".github/workflows/ci.yml") == [
        policy.Reference("owner/action@sha", ".github/workflows/ci.yml", 7)
    ]


def test_discover_references_ignores_non_executable_uses_keys() -> None:
    source = """
env:
  uses: not/an/action
jobs:
  build:
    steps:
      - uses: owner/action@sha
        with:
          uses: arbitrary-input
"""

    assert policy.discover_references(source, ".github/workflows/ci.yml") == [
        policy.Reference("owner/action@sha", ".github/workflows/ci.yml", 7)
    ]


def test_discover_references_finds_composite_action_steps_only() -> None:
    source = """
inputs:
  uses:
    default: arbitrary-input
runs:
  using: composite
  steps:
    - uses: owner/action@sha
      with:
        uses: arbitrary-input
"""

    assert policy.discover_references(source, ".github/actions/test/action.yml") == [
        policy.Reference("owner/action@sha", ".github/actions/test/action.yml", 8)
    ]


def selected_policy(**overrides: object) -> object:
    values: dict[str, object] = {
        "enabled": True,
        "allowed_actions": "selected",
        "sha_pinning_required": False,
        "github_owned_allowed": False,
        "verified_allowed": False,
        "patterns_allowed": (),
    }
    values.update(overrides)
    return policy.ActionsPolicy(**values)


@pytest.mark.parametrize(
    "value",
    ["./.github/actions/local", "$/shared/action", "docker://alpine:3.22"],
)
def test_local_and_container_references_do_not_need_external_policy(value: str) -> None:
    decision = policy.evaluate_reference(
        policy.Reference(value, "ci.yml", 1),
        selected_policy(),
        repository_owner="NVIDIA",
        is_verified_marketplace_action=lambda _owner, _repo: False,
    )

    assert decision.allowed


@pytest.mark.parametrize(
    ("value", "policy_overrides", "reason"),
    [
        ("NVIDIA/internal-action@v1", {}, "repository owner"),
        (
            "actions/checkout@v4",
            {"github_owned_allowed": True},
            "GitHub-owned",
        ),
        (
            "github/codeql-action/init@v3",
            {"github_owned_allowed": True},
            "GitHub-owned",
        ),
        (
            "oras-project/setup-oras@approved",
            {"patterns_allowed": ("oras-project/setup-oras@approved",)},
            "explicit policy pattern",
        ),
        (
            "softprops/action-gh-release@sha",
            {"patterns_allowed": ("softprops/action-gh-release@*",)},
            "explicit policy pattern",
        ),
    ],
)
def test_selected_policy_allows_supported_categories(
    value: str, policy_overrides: dict[str, object], reason: str
) -> None:
    decision = policy.evaluate_reference(
        policy.Reference(value, "ci.yml", 1),
        selected_policy(**policy_overrides),
        repository_owner="NVIDIA",
        is_verified_marketplace_action=lambda _owner, _repo: False,
    )

    assert decision.allowed
    assert reason in decision.reason


def test_verified_marketplace_applies_to_actions_but_not_reusable_workflows() -> None:
    live_policy = selected_policy(verified_allowed=True)

    def lookup(owner: str, repo: str) -> bool:
        return (owner, repo) == ("astral-sh", "setup-uv")

    action = policy.evaluate_reference(
        policy.Reference("astral-sh/setup-uv@sha", "ci.yml", 1),
        live_policy,
        repository_owner="NVIDIA",
        is_verified_marketplace_action=lookup,
    )
    workflow = policy.evaluate_reference(
        policy.Reference(
            "astral-sh/setup-uv/.github/workflows/test.yml@main", "ci.yml", 2
        ),
        live_policy,
        repository_owner="NVIDIA",
        is_verified_marketplace_action=lookup,
    )

    assert action.allowed
    assert "Marketplace-verified" in action.reason
    assert not workflow.allowed


def test_sha_pinning_applies_to_external_actions_not_reusable_workflows() -> None:
    live_policy = selected_policy(
        sha_pinning_required=True,
        patterns_allowed=("owner/repo@*", "owner/repo/.github/workflows/ci.yml@*"),
    )

    unpinned = policy.evaluate_reference(
        policy.Reference("owner/repo@v1", "ci.yml", 1),
        live_policy,
        repository_owner="NVIDIA",
        is_verified_marketplace_action=lambda _owner, _repo: False,
    )
    pinned = policy.evaluate_reference(
        policy.Reference(
            "owner/repo@0123456789012345678901234567890123456789", "ci.yml", 2
        ),
        live_policy,
        repository_owner="NVIDIA",
        is_verified_marketplace_action=lambda _owner, _repo: False,
    )
    reusable = policy.evaluate_reference(
        policy.Reference("owner/repo/.github/workflows/ci.yml@main", "ci.yml", 3),
        live_policy,
        repository_owner="NVIDIA",
        is_verified_marketplace_action=lambda _owner, _repo: False,
    )

    assert not unpinned.allowed
    assert "full-length commit SHA" in unpinned.reason
    assert pinned.allowed
    assert reusable.allowed


def test_negative_pattern_after_allow_pattern_wins() -> None:
    live_policy = selected_policy(
        patterns_allowed=("owner/*", "!owner/blocked@*"),
    )

    decision = policy.evaluate_reference(
        policy.Reference("owner/blocked@sha", "ci.yml", 1),
        live_policy,
        repository_owner="NVIDIA",
        is_verified_marketplace_action=lambda _owner, _repo: False,
    )

    assert not decision.allowed
    assert "blocked by policy pattern" in decision.reason


def test_policy_pattern_owner_and_repository_are_case_insensitive() -> None:
    live_policy = selected_policy(
        patterns_allowed=("swatinem/rust-cache@sha",),
    )

    decision = policy.evaluate_reference(
        policy.Reference("Swatinem/rust-cache@sha", "ci.yml", 1),
        live_policy,
        repository_owner="NVIDIA",
        is_verified_marketplace_action=lambda _owner, _repo: False,
    )

    assert decision.allowed


def test_enterprise_owned_organization_is_allowed() -> None:
    decision = policy.evaluate_reference(
        policy.Reference("sibling-org/action@sha", "ci.yml", 1),
        selected_policy(),
        repository_owner="NVIDIA",
        enterprise_organizations=frozenset({"nvidia", "sibling-org"}),
        is_verified_marketplace_action=lambda _owner, _repo: False,
    )

    assert decision.allowed
    assert "enterprise" in decision.reason


class FakeWeb:
    def __init__(self, responses: dict[str, str | Exception]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def get_text(self, url: str) -> str:
        self.calls.append(url)
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response


def test_marketplace_verification_is_bound_to_exact_repository() -> None:
    repository_url = "https://github.com/example/action"
    listing_url = "https://github.com/marketplace/actions/example"
    web = FakeWeb(
        {
            repository_url: '<a href="/marketplace/actions/example">Marketplace</a>',
            listing_url: (
                '{"isVerifiedOwner":true,"externalUsesPathPrefix":"different/action@"}'
            ),
        }
    )

    client = policy.MarketplaceClient(web)

    assert not client.is_verified_action("example", "action")


def test_marketplace_verification_accepts_exact_repository() -> None:
    repository_url = "https://github.com/docker/setup-buildx-action"
    listing_url = "https://github.com/marketplace/actions/docker-setup-buildx"
    web = FakeWeb(
        {
            repository_url: (
                '<a href="/marketplace/actions/docker-setup-buildx">Marketplace</a>'
            ),
            listing_url: (
                '{"isVerifiedOwner":true,'
                '"externalUsesPathPrefix":"docker/setup-buildx-action@"}'
            ),
        }
    )

    client = policy.MarketplaceClient(web)

    assert client.is_verified_action("docker", "setup-buildx-action")
    assert client.is_verified_action("docker", "setup-buildx-action")
    assert web.calls.count(repository_url) == 1


def test_marketplace_repository_identity_is_case_insensitive() -> None:
    repository_url = "https://github.com/Docker/Setup-Buildx-Action"
    listing_url = "https://github.com/marketplace/actions/docker-setup-buildx"
    web = FakeWeb(
        {
            repository_url: (
                '<a href="/marketplace/actions/docker-setup-buildx">Marketplace</a>'
            ),
            listing_url: (
                '{"isVerifiedOwner":true,'
                '"externalUsesPathPrefix":"docker/setup-buildx-action@"}'
            ),
        }
    )

    assert policy.MarketplaceClient(web).is_verified_action(
        "Docker", "Setup-Buildx-Action"
    )


def test_marketplace_ambiguous_metadata_fails_closed() -> None:
    repository_url = "https://github.com/example/action"
    listing_url = "https://github.com/marketplace/actions/example"
    web = FakeWeb(
        {
            repository_url: '<a href="/marketplace/actions/example">Marketplace</a>',
            listing_url: '{"externalUsesPathPrefix":"example/action@"}',
        }
    )

    with pytest.raises(policy.EvaluationError, match="verification metadata"):
        policy.MarketplaceClient(web).is_verified_action("example", "action")


def test_policy_client_reads_selected_policy_without_copying_patterns() -> None:
    permissions_url = (
        "https://api.github.com/repos/NVIDIA/OpenShell/actions/permissions"
    )
    selected_url = f"{permissions_url}/selected-actions"
    api = FakeWeb(
        {
            permissions_url: (
                '{"enabled":true,"allowed_actions":"selected",'
                '"sha_pinning_required":false}'
            ),
            selected_url: (
                '{"github_owned_allowed":true,"verified_allowed":true,'
                '"patterns_allowed":["owner/action@sha"]}'
            ),
        }
    )

    live_policy = policy.PolicyClient(api).get_policy("NVIDIA/OpenShell")

    assert live_policy == selected_policy(
        github_owned_allowed=True,
        verified_allowed=True,
        patterns_allowed=("owner/action@sha",),
    )


def test_policy_client_rejects_invalid_or_disabled_policy() -> None:
    permissions_url = (
        "https://api.github.com/repos/NVIDIA/OpenShell/actions/permissions"
    )

    with pytest.raises(policy.EvaluationError, match="disabled"):
        policy.PolicyClient(
            FakeWeb(
                {
                    permissions_url: (
                        '{"enabled":false,"allowed_actions":"selected",'
                        '"sha_pinning_required":false}'
                    )
                }
            )
        ).get_policy("NVIDIA/OpenShell")


class FakeGitHub:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.posts: list[tuple[str, dict[str, object]]] = []

    def get_json(self, url: str) -> object:
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response

    def post_json(self, url: str, payload: object) -> object:
        assert isinstance(payload, dict)
        self.posts.append((url, cast("dict[str, object]", payload)))
        return {"ok": True}


class FakeGraphQL:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses

    def post_json(self, _url: str, _payload: object) -> object:
        return self.responses.pop(0)


def test_enterprise_client_resolves_only_repository_owner_enterprise() -> None:
    client = FakeGraphQL(
        [
            {
                "data": {
                    "viewer": {
                        "enterprises": {
                            "nodes": [{"id": "enterprise-1"}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            },
            {
                "data": {
                    "node": {
                        "organizations": {
                            "nodes": [{"login": "NVIDIA"}, {"login": "Sibling-Org"}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            },
        ]
    )

    assert policy.EnterpriseClient(client).organizations_for("nvidia") == frozenset(
        {"nvidia", "sibling-org"}
    )


def test_source_client_decodes_wrapped_base64() -> None:
    content = (
        "jobs:\n  test:\n    uses: owner/workflows/.github/workflows/ci.yml@main\n"
    )
    encoded = base64.encodebytes(content.encode()).decode()
    url = (
        "https://api.github.com/repos/fork/OpenShell/contents/"
        ".github/workflows/ci.yml?ref=head"
    )
    client = FakeGitHub(
        {url: {"encoding": "base64", "content": encoded, "size": len(content)}}
    )

    assert (
        policy.GitHubSourceClient(client).content(
            "fork/OpenShell", ".github/workflows/ci.yml", "head"
        )
        == content
    )


def test_source_client_fails_closed_when_expected_content_is_missing() -> None:
    url = (
        "https://api.github.com/repos/fork/OpenShell/contents/"
        ".github/workflows/ci.yml?ref=head"
    )
    client = FakeGitHub({url: policy.HttpError(404, url, "Not Found")})

    with pytest.raises(policy.HttpError, match="404"):
        policy.GitHubSourceClient(client).content(
            "fork/OpenShell", ".github/workflows/ci.yml", "head"
        )


def test_source_client_fails_closed_on_incomplete_pull_file_list() -> None:
    repository = "NVIDIA/OpenShell"
    url = f"https://api.github.com/repos/{repository}/pulls/3624/files?per_page=100&page=1"
    client = FakeGitHub({url: []})

    with pytest.raises(policy.EvaluationError, match="incomplete"):
        policy.GitHubSourceClient(client).pull_files(repository, 3624, 1)


def test_workflow_run_binds_pull_request_to_current_head() -> None:
    head_sha = "b" * 40
    base_sha = "a" * 40
    repository = "NVIDIA/OpenShell"
    pull_url = f"https://api.github.com/repos/{repository}/pulls/3624"
    files_url = f"{pull_url}/files?per_page=100&page=1"
    client = FakeGitHub(
        {
            pull_url: {
                "number": 3624,
                "changed_files": 0,
                "base": {"sha": base_sha, "repo": {"full_name": repository}},
                "head": {"sha": head_sha, "repo": {"full_name": "fork/OpenShell"}},
            },
            files_url: [],
        }
    )
    event = {
        "repository": {"full_name": repository},
        "workflow_run": {
            "event": "pull_request",
            "conclusion": "success",
            "head_sha": head_sha,
            "path": ".github/workflows/workflow-policy-request.yml",
            "pull_requests": [{"number": 3624}],
        },
    }

    assert policy.run_workflow_run(event, client, "https://example.test/run") == 0
    assert [payload["state"] for _, payload in client.posts] == [
        "pending",
        "success",
    ]


def test_workflow_run_skips_stale_pull_request_head() -> None:
    run_sha = "a" * 40
    current_sha = "b" * 40
    repository = "NVIDIA/OpenShell"
    pull_url = f"https://api.github.com/repos/{repository}/pulls/3624"
    client = FakeGitHub(
        {
            pull_url: {
                "number": 3624,
                "changed_files": 0,
                "base": {"sha": "c" * 40, "repo": {"full_name": repository}},
                "head": {
                    "sha": current_sha,
                    "repo": {"full_name": "fork/OpenShell"},
                },
            }
        }
    )
    event = {
        "repository": {"full_name": repository},
        "workflow_run": {
            "event": "pull_request",
            "conclusion": "success",
            "head_sha": run_sha,
            "path": ".github/workflows/workflow-policy-request.yml",
            "pull_requests": [{"number": 3624}],
        },
    }

    assert policy.run_workflow_run(event, client, "https://example.test/run") == 0
    assert client.posts == []


def test_merge_group_scans_complete_candidate_tree() -> None:
    merge_sha = "a" * 40
    repository = "NVIDIA/OpenShell"
    tree_url = (
        f"https://api.github.com/repos/{repository}/git/trees/{merge_sha}?recursive=1"
    )
    client = FakeGitHub({tree_url: {"truncated": False, "tree": []}})

    assert (
        policy.run_merge_group(
            repository=repository,
            head_sha=merge_sha,
            github_client=client,
            target_url="https://example.test/run",
        )
        == 0
    )
    assert [payload["state"] for _, payload in client.posts] == [
        "pending",
        "success",
    ]


def test_merge_group_fails_closed_on_truncated_candidate_tree() -> None:
    merge_sha = "a" * 40
    repository = "NVIDIA/OpenShell"
    tree_url = (
        f"https://api.github.com/repos/{repository}/git/trees/{merge_sha}?recursive=1"
    )
    client = FakeGitHub({tree_url: {"truncated": True, "tree": []}})

    assert (
        policy.run_merge_group(
            repository=repository,
            head_sha=merge_sha,
            github_client=client,
            target_url="https://example.test/run",
        )
        == 1
    )
    assert [payload["state"] for _, payload in client.posts] == [
        "pending",
        "failure",
    ]
