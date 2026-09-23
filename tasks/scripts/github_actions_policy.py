#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Validate changed GitHub Actions references against the live repository policy."""

from __future__ import annotations

import base64
import fnmatch
import html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

if TYPE_CHECKING:
    from collections.abc import Callable

API_ROOT = "https://api.github.com"
MARKETPLACE_ROOT = "https://github.com"
STATUS_CONTEXT = "OpenShell / Workflow Policy"
MAX_DEFINITION_BYTES = 1024 * 1024
MAX_DEFINITION_COUNT = 1000
MAX_TOTAL_DEFINITION_BYTES = 10 * 1024 * 1024
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
MARKETPLACE_LINK_RE = re.compile(
    r'href=["\']/marketplace/actions/([A-Za-z0-9_-]+)["\']'
)


class EvaluationError(RuntimeError):
    """A policy input could not be evaluated safely."""


class HttpError(EvaluationError):
    def __init__(self, status: int, url: str, message: str) -> None:
        super().__init__(f"GitHub request failed ({status}) for {url}: {message}")
        self.status = status
        self.url = url


@dataclass(frozen=True)
class Reference:
    value: str
    path: str
    line: int


@dataclass(frozen=True)
class ActionsPolicy:
    enabled: bool
    allowed_actions: str
    sha_pinning_required: bool
    github_owned_allowed: bool = False
    verified_allowed: bool = False
    patterns_allowed: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class TextClient(Protocol):
    def get_text(self, url: str) -> str: ...


class JsonClient(Protocol):
    def post_json(self, url: str, payload: object) -> object: ...


def _parse_uses_value(value: str, path: str, line: int) -> str:
    if not value:
        raise EvaluationError(f"empty uses value at {path}:{line}")
    if "${{" in value:
        raise EvaluationError(
            f"dynamic uses value cannot be policy-checked at {path}:{line}"
        )
    if any(character.isspace() for character in value):
        raise EvaluationError(f"invalid scalar uses value at {path}:{line}")
    return value


def discover_references(source: str, path: str) -> list[Reference]:
    try:
        document = yaml.compose(source, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise EvaluationError(f"invalid YAML in {path}: {exc}") from exc
    if document is None:
        return []

    if not isinstance(document, MappingNode):
        raise EvaluationError(f"action definition must be a mapping in {path}")

    def values_for(mapping: MappingNode, name: str) -> list[Node]:
        return [
            value
            for key, value in mapping.value
            if isinstance(key, ScalarNode) and key.value == name
        ]

    references: list[Reference] = []

    def collect_step_or_job(mapping: MappingNode) -> None:
        for value in values_for(mapping, "uses"):
            line = value.start_mark.line + 1
            if (
                not isinstance(value, ScalarNode)
                or value.tag != "tag:yaml.org,2002:str"
            ):
                raise EvaluationError(f"uses value must be a string at {path}:{line}")
            references.append(
                Reference(_parse_uses_value(value.value, path, line), path, line)
            )

    if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", path, re.IGNORECASE):
        for jobs_value in values_for(document, "jobs"):
            if not isinstance(jobs_value, MappingNode):
                continue
            for _, job_value in jobs_value.value:
                if not isinstance(job_value, MappingNode):
                    continue
                collect_step_or_job(job_value)
                for steps_value in values_for(job_value, "steps"):
                    if isinstance(steps_value, SequenceNode):
                        for step_value in steps_value.value:
                            if isinstance(step_value, MappingNode):
                                collect_step_or_job(step_value)
    else:
        for runs_value in values_for(document, "runs"):
            if not isinstance(runs_value, MappingNode):
                continue
            for steps_value in values_for(runs_value, "steps"):
                if isinstance(steps_value, SequenceNode):
                    for step_value in steps_value.value:
                        if isinstance(step_value, MappingNode):
                            collect_step_or_job(step_value)
    return references


def added_references(base: list[Reference], head: list[Reference]) -> list[Reference]:
    remaining = Counter(reference.value for reference in base)
    added: list[Reference] = []
    for reference in head:
        if remaining[reference.value] > 0:
            remaining[reference.value] -= 1
        else:
            added.append(reference)
    return added


def is_action_definition(path: str) -> bool:
    lowered = path.lower()
    if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", lowered):
        return True
    return bool(re.fullmatch(r"\.github/actions/.+/action\.ya?ml", lowered))


def _split_external_reference(value: str) -> tuple[str, str, str, bool]:
    if "@" not in value:
        raise EvaluationError(
            f"external reference {value!r} has no @ revision and cannot be evaluated"
        )
    target, revision = value.rsplit("@", 1)
    parts = target.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1] or not revision:
        raise EvaluationError(f"invalid external reference {value!r}")
    reusable = len(parts) >= 5 and parts[2:4] == [".github", "workflows"]
    return parts[0], parts[1], revision, reusable


def _pattern_decision(value: str, patterns: tuple[str, ...]) -> bool | None:
    def normalize_identity(candidate: str) -> str:
        target, separator, revision = candidate.rpartition("@")
        parts = target.split("/")
        if len(parts) >= 2:
            parts[0] = parts[0].casefold()
            parts[1] = parts[1].casefold()
        normalized = "/".join(parts)
        return f"{normalized}{separator}{revision}" if separator else normalized

    normalized_value = normalize_identity(value)
    decision: bool | None = None
    for raw_pattern in patterns:
        deny = raw_pattern.startswith("!")
        pattern = raw_pattern[1:] if deny else raw_pattern
        if pattern and fnmatch.fnmatchcase(
            normalized_value, normalize_identity(pattern)
        ):
            decision = not deny
    return decision


def evaluate_reference(
    reference: Reference,
    policy: ActionsPolicy,
    *,
    repository_owner: str,
    enterprise_organizations: frozenset[str] = frozenset(),
    is_verified_marketplace_action: Callable[[str, str], bool],
) -> Decision:
    value = reference.value
    if value.startswith(("./", "$/", "docker://")):
        return Decision(True, "local or container reference")
    if not policy.enabled:
        return Decision(False, "GitHub Actions is disabled for the repository")

    owner, repository, revision, reusable = _split_external_reference(value)
    if (
        policy.sha_pinning_required
        and not reusable
        and not FULL_SHA_RE.fullmatch(revision)
    ):
        return Decision(False, "external actions must use a full-length commit SHA")

    if policy.allowed_actions == "all":
        return Decision(True, "repository policy allows all actions")
    if policy.allowed_actions == "local_only":
        return Decision(False, "repository policy allows only local actions")
    if policy.allowed_actions != "selected":
        raise EvaluationError(
            f"unsupported allowed_actions value {policy.allowed_actions!r}"
        )

    pattern_decision = _pattern_decision(value, policy.patterns_allowed)
    if pattern_decision is False:
        return Decision(False, "reference is blocked by policy pattern")
    if pattern_decision is True:
        return Decision(True, "reference matches an explicit policy pattern")

    if owner.casefold() == repository_owner.casefold():
        return Decision(True, "reference belongs to the repository owner")
    if owner.casefold() in enterprise_organizations:
        return Decision(True, "reference belongs to the repository owner's enterprise")
    if policy.github_owned_allowed and owner.casefold() in {"actions", "github"}:
        return Decision(True, "reference is GitHub-owned")
    if (
        policy.verified_allowed
        and not reusable
        and is_verified_marketplace_action(owner, repository)
    ):
        return Decision(True, "action belongs to a Marketplace-verified creator")
    return Decision(
        False, "reference is not allowed by the effective repository policy"
    )


class HttpClient:
    def __init__(self, token: str = "") -> None:
        self.token = token

    def _request(
        self, url: str, *, method: str = "GET", payload: object | None = None
    ) -> str:
        accept = (
            "application/vnd.github+json"
            if urllib.parse.urlsplit(url).hostname == "api.github.com"
            else "text/html,application/xhtml+xml"
        )
        headers = {
            "Accept": accept,
            "User-Agent": "OpenShell-workflow-policy-check",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read(MAX_DEFINITION_BYTES + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.reason or "HTTP error"
            raise HttpError(exc.code, url, str(detail)) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise EvaluationError(f"GitHub request failed for {url}: {exc}") from exc
        if len(body) > MAX_DEFINITION_BYTES:
            raise EvaluationError(f"response from {url} exceeds size limit")
        return body.decode("utf-8")

    def get_text(self, url: str) -> str:
        return self._request(url)

    def get_json(self, url: str) -> object:
        try:
            return json.loads(self.get_text(url))
        except json.JSONDecodeError as exc:
            raise EvaluationError(f"GitHub returned invalid JSON for {url}") from exc

    def post_json(self, url: str, payload: object) -> object:
        try:
            return json.loads(self._request(url, method="POST", payload=payload))
        except json.JSONDecodeError as exc:
            raise EvaluationError(f"GitHub returned invalid JSON for {url}") from exc


def _load_mapping(client: TextClient, url: str) -> dict[str, object]:
    try:
        value = json.loads(client.get_text(url))
    except json.JSONDecodeError as exc:
        raise EvaluationError(f"GitHub returned invalid policy JSON for {url}") from exc
    if not isinstance(value, dict):
        raise EvaluationError(f"GitHub returned an invalid policy object for {url}")
    return value


class PolicyClient:
    def __init__(self, client: TextClient) -> None:
        self.client = client

    def get_policy(self, repository: str) -> ActionsPolicy:
        permissions_url = f"{API_ROOT}/repos/{repository}/actions/permissions"
        permissions = _load_mapping(self.client, permissions_url)
        enabled = permissions.get("enabled")
        allowed_actions = permissions.get("allowed_actions")
        sha_pinning = permissions.get("sha_pinning_required", False)
        if enabled is not True:
            raise EvaluationError("GitHub Actions is disabled for the repository")
        if allowed_actions not in {"all", "local_only", "selected"}:
            raise EvaluationError("GitHub returned an invalid allowed_actions policy")
        if not isinstance(sha_pinning, bool):
            raise EvaluationError("GitHub returned an invalid SHA-pinning policy")
        if allowed_actions != "selected":
            return ActionsPolicy(True, str(allowed_actions), sha_pinning)

        selected_url = f"{permissions_url}/selected-actions"
        selected = _load_mapping(self.client, selected_url)
        github_owned = selected.get("github_owned_allowed", False)
        verified = selected.get("verified_allowed", False)
        patterns = selected.get("patterns_allowed", [])
        if not isinstance(github_owned, bool) or not isinstance(verified, bool):
            raise EvaluationError("GitHub returned invalid selected-actions flags")
        if not isinstance(patterns, list) or not all(
            isinstance(pattern, str) for pattern in patterns
        ):
            raise EvaluationError("GitHub returned invalid selected-actions patterns")
        return ActionsPolicy(
            True,
            "selected",
            sha_pinning,
            github_owned,
            verified,
            tuple(pattern for pattern in patterns if isinstance(pattern, str)),
        )


class EnterpriseClient:
    ENTERPRISES_QUERY = """
query($cursor: String) {
  viewer {
    enterprises(first: 100, after: $cursor) {
      nodes { id }
      pageInfo { hasNextPage endCursor }
    }
  }
}
"""
    ORGANIZATIONS_QUERY = """
query($id: ID!, $cursor: String) {
  node(id: $id) {
    ... on Enterprise {
      organizations(first: 100, after: $cursor) {
        nodes { login }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

    def __init__(self, client: JsonClient) -> None:
        self.client = client

    def _query(self, query: str, variables: dict[str, object]) -> dict[str, object]:
        value = self.client.post_json(
            f"{API_ROOT}/graphql", {"query": query, "variables": variables}
        )
        response = _require_mapping(value, "GraphQL response")
        if response.get("errors"):
            raise EvaluationError("GitHub could not resolve enterprise ownership")
        return _require_mapping(response.get("data"), "GraphQL response data")

    def _enterprise_ids(self) -> list[str]:
        enterprise_ids: list[str] = []
        cursor: str | None = None
        for _ in range(100):
            data = self._query(self.ENTERPRISES_QUERY, {"cursor": cursor})
            viewer = _require_mapping(data.get("viewer"), "GraphQL viewer")
            connection = _require_mapping(
                viewer.get("enterprises"), "GraphQL enterprises"
            )
            nodes = connection.get("nodes")
            if not isinstance(nodes, list):
                raise EvaluationError("GitHub returned invalid enterprise membership")
            for node_value in nodes:
                node = _require_mapping(node_value, "GraphQL enterprise")
                enterprise_ids.append(_require_string(node, "id", "enterprise ID"))
            page_info = _require_mapping(
                connection.get("pageInfo"), "GraphQL enterprise page info"
            )
            if page_info.get("hasNextPage") is False:
                return enterprise_ids
            cursor = _require_string(page_info, "endCursor", "enterprise page cursor")
        raise EvaluationError("enterprise membership exceeds pagination limit")

    def _organizations(self, enterprise_id: str) -> frozenset[str]:
        organizations: set[str] = set()
        cursor: str | None = None
        for _ in range(100):
            data = self._query(
                self.ORGANIZATIONS_QUERY, {"id": enterprise_id, "cursor": cursor}
            )
            enterprise = _require_mapping(data.get("node"), "GraphQL enterprise")
            connection = _require_mapping(
                enterprise.get("organizations"), "GraphQL enterprise organizations"
            )
            nodes = connection.get("nodes")
            if not isinstance(nodes, list):
                raise EvaluationError(
                    "GitHub returned invalid enterprise organizations"
                )
            for node_value in nodes:
                node = _require_mapping(node_value, "GraphQL organization")
                organizations.add(
                    _require_string(node, "login", "organization login").casefold()
                )
            page_info = _require_mapping(
                connection.get("pageInfo"), "GraphQL organization page info"
            )
            if page_info.get("hasNextPage") is False:
                return frozenset(organizations)
            cursor = _require_string(page_info, "endCursor", "organization page cursor")
        raise EvaluationError("enterprise organization list exceeds pagination limit")

    def organizations_for(self, repository_owner: str) -> frozenset[str]:
        owner = repository_owner.casefold()
        for enterprise_id in self._enterprise_ids():
            organizations = self._organizations(enterprise_id)
            if owner in organizations:
                return organizations
        raise EvaluationError(
            "enterprise-read token cannot resolve the repository owner's enterprise"
        )


class MarketplaceClient:
    def __init__(self, client: TextClient) -> None:
        self.client = client
        self.cache: dict[tuple[str, str], bool] = {}

    def is_verified_action(self, owner: str, repository: str) -> bool:
        key = (owner.casefold(), repository.casefold())
        if key in self.cache:
            return self.cache[key]

        repository_url = f"{MARKETPLACE_ROOT}/{urllib.parse.quote(owner)}/{urllib.parse.quote(repository)}"
        try:
            repository_page = self.client.get_text(repository_url)
        except HttpError as exc:
            if exc.status == 404:
                self.cache[key] = False
                return False
            raise
        slugs = sorted(set(MARKETPLACE_LINK_RE.findall(html.unescape(repository_page))))
        expected_prefix = f"{owner}/{repository}@"
        prefix_marker = json.dumps(expected_prefix)
        for slug in slugs:
            listing_url = f"{MARKETPLACE_ROOT}/marketplace/actions/{slug}"
            listing_page = self.client.get_text(listing_url)
            marker = re.escape(f'"externalUsesPathPrefix":{prefix_marker}')
            forward = re.findall(
                rf'"isVerifiedOwner":(true|false)[^{{}}]{{0,2000}}{marker}',
                listing_page,
                flags=re.IGNORECASE,
            )
            reverse = re.findall(
                rf'{marker}[^{{}}]{{0,2000}}"isVerifiedOwner":(true|false)',
                listing_page,
                flags=re.IGNORECASE,
            )
            verification_values = {value == "true" for value in [*forward, *reverse]}
            if not verification_values and not re.search(
                marker, listing_page, flags=re.IGNORECASE
            ):
                continue
            if len(verification_values) != 1:
                raise EvaluationError(
                    f"Marketplace verification metadata is ambiguous for {owner}/{repository}"
                )
            verified = verification_values.pop()
            self.cache[key] = verified
            return verified

        if re.search(re.escape(prefix_marker), repository_page, flags=re.IGNORECASE):
            raise EvaluationError(
                f"Marketplace verification metadata is ambiguous for {owner}/{repository}"
            )
        self.cache[key] = False
        return False


class GitHubSourceClient:
    def __init__(self, client: HttpClient) -> None:
        self.client = client

    def pull_files(
        self, repository: str, number: int, expected_count: int
    ) -> list[dict[str, object]]:
        files: list[dict[str, object]] = []
        for page in range(1, 31):
            url = (
                f"{API_ROOT}/repos/{repository}/pulls/{number}/files"
                f"?per_page=100&page={page}"
            )
            value = self.client.get_json(url)
            if not isinstance(value, list) or not all(
                isinstance(item, dict) for item in value
            ):
                raise EvaluationError(
                    "GitHub returned an invalid pull-request file list"
                )
            batch = [_require_mapping(item, "pull-request file") for item in value]
            files.extend(batch)
            if len(batch) < 100:
                if len(files) != expected_count:
                    raise EvaluationError(
                        "GitHub returned an incomplete pull-request file list "
                        f"({len(files)} of {expected_count} files)"
                    )
                return files
        raise EvaluationError(
            "pull request exceeds GitHub's 3,000-file policy-evaluation limit"
        )

    def definition_paths(self, repository: str, revision: str) -> list[str]:
        encoded_revision = urllib.parse.quote(revision, safe="")
        url = f"{API_ROOT}/repos/{repository}/git/trees/{encoded_revision}?recursive=1"
        value = self.client.get_json(url)
        tree_data = _require_mapping(value, "Git tree")
        if tree_data.get("truncated") is not False:
            raise EvaluationError("GitHub returned a truncated merge-group tree")
        tree = tree_data.get("tree")
        if not isinstance(tree, list):
            raise EvaluationError("GitHub returned an invalid merge-group tree")
        paths: list[str] = []
        total_size = 0
        for entry_value in tree:
            entry = _require_mapping(entry_value, "Git tree entry")
            path = entry.get("path")
            entry_type = entry.get("type")
            if not isinstance(path, str) or not isinstance(entry_type, str):
                raise EvaluationError("GitHub returned an invalid Git tree entry")
            if entry_type == "blob" and is_action_definition(path):
                size = entry.get("size")
                if not isinstance(size, int) or size < 0:
                    raise EvaluationError(
                        "GitHub returned an invalid Git tree entry size"
                    )
                paths.append(path)
                total_size += size
                if len(paths) > MAX_DEFINITION_COUNT:
                    raise EvaluationError("merge group has too many action definitions")
                if total_size > MAX_TOTAL_DEFINITION_BYTES:
                    raise EvaluationError(
                        "merge-group action definitions exceed size limit"
                    )
        return paths

    def content(self, repository: str, path: str, revision: str) -> str:
        encoded_path = urllib.parse.quote(path, safe="/")
        encoded_revision = urllib.parse.quote(revision, safe="")
        url = (
            f"{API_ROOT}/repos/{repository}/contents/{encoded_path}"
            f"?ref={encoded_revision}"
        )
        value = _require_mapping(self.client.get_json(url), "file content")
        if value.get("encoding") != "base64":
            raise EvaluationError(f"GitHub returned invalid file content for {path}")
        encoded = value.get("content")
        size = value.get("size", 0)
        if not isinstance(encoded, str) or not isinstance(size, int):
            raise EvaluationError(f"GitHub returned invalid file content for {path}")
        if size > MAX_DEFINITION_BYTES:
            raise EvaluationError(f"{path} exceeds the workflow policy size limit")
        try:
            decoded = base64.b64decode("".join(encoded.split()), validate=True)
            return decoded.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise EvaluationError(
                f"GitHub returned invalid file content for {path}"
            ) from exc


def collect_added_references(
    source: GitHubSourceClient,
    *,
    repository: str,
    pull_number: int,
    base_repository: str,
    base_sha: str,
    head_repository: str,
    head_sha: str,
    changed_files: int,
) -> list[Reference]:
    added: list[Reference] = []
    for changed_file in source.pull_files(repository, pull_number, changed_files):
        filename = changed_file.get("filename")
        previous = changed_file.get("previous_filename", filename)
        status = changed_file.get("status")
        if not isinstance(filename, str) or not isinstance(previous, str):
            raise EvaluationError("GitHub returned an invalid changed file entry")
        if not is_action_definition(filename) and not is_action_definition(previous):
            continue

        base_text = ""
        if status != "added" and is_action_definition(previous):
            base_text = source.content(base_repository, previous, base_sha)
        head_text = ""
        if status != "removed" and is_action_definition(filename):
            head_text = source.content(head_repository, filename, head_sha)
        base_references = discover_references(base_text, previous)
        head_references = discover_references(head_text, filename)
        added.extend(added_references(base_references, head_references))
    return added


def collect_all_references(
    source: GitHubSourceClient, *, repository: str, revision: str
) -> list[Reference]:
    references: list[Reference] = []
    for path in source.definition_paths(repository, revision):
        references.extend(
            discover_references(source.content(repository, path, revision), path)
        )
    return references


def _require_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise EvaluationError(f"event is missing {label}")
    return cast("dict[str, object]", value)


def _require_string(mapping: dict[str, object], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise EvaluationError(f"event is missing {label}")
    return value


def _command_escape(value: str) -> str:
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def emit_error(message: str, reference: Reference | None = None) -> None:
    if reference is None:
        print(f"::error title=Workflow policy::{_command_escape(message)}")
        return
    print(
        f"::error file={_command_escape(reference.path)},line={reference.line},"
        f"title=Disallowed workflow reference::{_command_escape(message)}"
    )


def append_summary(lines: list[str]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with Path(summary_path).open("a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")


class StatusPublisher:
    def __init__(
        self, client: HttpClient, repository: str, sha: str, target_url: str
    ) -> None:
        self.client = client
        self.url = f"{API_ROOT}/repos/{repository}/statuses/{sha}"
        self.target_url = target_url

    def publish(self, state: str, description: str) -> None:
        payload = {
            "state": state,
            "context": STATUS_CONTEXT,
            "description": description[:140],
            "target_url": self.target_url,
        }
        self.client.post_json(self.url, payload)
        print(f"{STATUS_CONTEXT}: {state} - {description}")


def evaluate_and_publish(
    references: list[Reference],
    *,
    repository: str,
    publisher: StatusPublisher,
    empty_description: str,
) -> int:
    policy_token = os.environ.get("ACTIONS_POLICY_READ_TOKEN", "")
    enterprise_token = os.environ.get("ACTIONS_ENTERPRISE_READ_TOKEN", "")
    if not references:
        publisher.publish("success", empty_description)
        append_summary(["## Workflow policy", f"{empty_description}."])
        return 0
    if not policy_token:
        raise EvaluationError(
            "ACTIONS_POLICY_READ_TOKEN is not configured; add a fine-grained "
            "token with repository Administration (read)"
        )

    effective_policy = PolicyClient(HttpClient(policy_token)).get_policy(repository)
    marketplace = MarketplaceClient(HttpClient())
    repository_owner = repository.split("/", 1)[0]
    enterprise_organizations: frozenset[str] = frozenset()
    if effective_policy.allowed_actions == "selected":
        if not enterprise_token:
            raise EvaluationError(
                "ACTIONS_ENTERPRISE_READ_TOKEN is not configured; add a classic "
                "token with read:enterprise"
            )
        enterprise_organizations = EnterpriseClient(
            HttpClient(enterprise_token)
        ).organizations_for(repository_owner)
    rejected: list[tuple[Reference, str]] = []
    for reference in references:
        decision = evaluate_reference(
            reference,
            effective_policy,
            repository_owner=repository_owner,
            enterprise_organizations=enterprise_organizations,
            is_verified_marketplace_action=marketplace.is_verified_action,
        )
        if not decision.allowed:
            rejected.append((reference, decision.reason))
            emit_error(f"{reference.value}: {decision.reason}", reference)

    if rejected:
        publisher.publish(
            "failure", f"{len(rejected)} workflow reference(s) violate policy"
        )
        append_summary(
            [
                "## Workflow policy",
                f"Rejected {len(rejected)} reference(s):",
                *[
                    f"- `{reference.value}` in `{reference.path}:{reference.line}` — {reason}"
                    for reference, reason in rejected
                ],
            ]
        )
        return 1

    publisher.publish("success", f"{len(references)} workflow reference(s) allowed")
    append_summary(
        [
            "## Workflow policy",
            f"All {len(references)} `uses:` references match the effective policy.",
        ]
    )
    return 0


def run_pull_request(
    pull: dict[str, object],
    *,
    repository: str,
    github_client: HttpClient,
    target_url: str,
) -> int:
    base = _require_mapping(pull.get("base"), "pull_request.base")
    head = _require_mapping(pull.get("head"), "pull_request.head")
    base_repo = _require_mapping(base.get("repo"), "pull_request.base.repo")
    head_repo = _require_mapping(head.get("repo"), "pull_request.head.repo")

    base_repository = _require_string(base_repo, "full_name", "base repository")
    head_repository = _require_string(head_repo, "full_name", "head repository")
    base_sha = _require_string(base, "sha", "base SHA")
    head_sha = _require_string(head, "sha", "head SHA")
    pull_number = pull.get("number")
    changed_files = pull.get("changed_files")
    if not isinstance(pull_number, int):
        raise EvaluationError("event is missing pull request number")
    if not isinstance(changed_files, int) or changed_files < 0:
        raise EvaluationError("pull request has an invalid changed-files count")

    publisher = StatusPublisher(github_client, repository, head_sha, target_url)
    publisher.publish("pending", "Checking changed workflow references")
    try:
        references = collect_added_references(
            GitHubSourceClient(github_client),
            repository=repository,
            pull_number=pull_number,
            base_repository=base_repository,
            base_sha=base_sha,
            head_repository=head_repository,
            head_sha=head_sha,
            changed_files=changed_files,
        )
        return evaluate_and_publish(
            references,
            repository=repository,
            publisher=publisher,
            empty_description="No new or changed workflow references",
        )
    except EvaluationError as exc:
        emit_error(str(exc))
        publisher.publish("failure", "Workflow policy evaluation failed")
        append_summary(["## Workflow policy", f"Evaluation failed: {exc}"])
        return 1


def run_merge_group(
    *,
    repository: str,
    head_sha: str,
    github_client: HttpClient,
    target_url: str,
) -> int:
    publisher = StatusPublisher(github_client, repository, head_sha, target_url)
    publisher.publish("pending", "Checking queued workflow references")
    try:
        references = collect_all_references(
            GitHubSourceClient(github_client),
            repository=repository,
            revision=head_sha,
        )
        return evaluate_and_publish(
            references,
            repository=repository,
            publisher=publisher,
            empty_description="No workflow references in queued revision",
        )
    except EvaluationError as exc:
        emit_error(str(exc))
        publisher.publish("failure", "Merge-group policy evaluation failed")
        append_summary(["## Workflow policy", f"Evaluation failed: {exc}"])
        return 1


def _associated_pull_number(
    workflow_run: dict[str, object],
    *,
    repository: str,
    head_sha: str,
    github_client: HttpClient,
) -> int:
    pull_values = workflow_run.get("pull_requests")
    numbers: set[int] = set()
    if isinstance(pull_values, list):
        for pull_value in pull_values:
            pull = _require_mapping(pull_value, "workflow-run pull request")
            number = pull.get("number")
            if isinstance(number, int):
                numbers.add(number)
    if len(numbers) != 1:
        pulls_url = (
            f"{API_ROOT}/repos/{repository}/commits/{head_sha}/pulls?per_page=100"
        )
        associated = github_client.get_json(pulls_url)
        if not isinstance(associated, list):
            raise EvaluationError("GitHub returned invalid associated pull requests")
        numbers = set()
        for value in associated:
            pull = _require_mapping(value, "associated pull request")
            number = pull.get("number")
            if isinstance(number, int):
                numbers.add(number)
    if len(numbers) != 1:
        raise EvaluationError("workflow run is not bound to exactly one pull request")
    return numbers.pop()


def run_workflow_run(
    event_mapping: dict[str, object], github_client: HttpClient, target_url: str
) -> int:
    repository_data = _require_mapping(event_mapping.get("repository"), "repository")
    workflow_run = _require_mapping(event_mapping.get("workflow_run"), "workflow_run")
    repository = _require_string(repository_data, "full_name", "repository.full_name")
    head_sha = _require_string(workflow_run, "head_sha", "workflow-run head SHA")
    trigger = _require_string(workflow_run, "event", "workflow-run event")
    conclusion = workflow_run.get("conclusion")
    workflow_path = _require_string(workflow_run, "path", "workflow-run path")
    if workflow_path != ".github/workflows/workflow-policy-request.yml":
        raise EvaluationError(f"unexpected workflow-run path {workflow_path!r}")
    if trigger not in {"pull_request", "merge_group"}:
        raise EvaluationError(f"unsupported workflow-run event {trigger!r}")

    if trigger == "merge_group":
        publisher = StatusPublisher(github_client, repository, head_sha, target_url)
        if conclusion != "success":
            publisher.publish("failure", "Workflow policy request did not succeed")
            return 1
        return run_merge_group(
            repository=repository,
            head_sha=head_sha,
            github_client=github_client,
            target_url=target_url,
        )

    pull_number = _associated_pull_number(
        workflow_run,
        repository=repository,
        head_sha=head_sha,
        github_client=github_client,
    )
    pull_url = f"{API_ROOT}/repos/{repository}/pulls/{pull_number}"
    pull = _require_mapping(github_client.get_json(pull_url), "pull request")
    head = _require_mapping(pull.get("head"), "pull_request.head")
    current_head_sha = _require_string(head, "sha", "pull-request head SHA")
    base = _require_mapping(pull.get("base"), "pull_request.base")
    base_repo = _require_mapping(base.get("repo"), "pull_request.base.repo")
    base_repository = _require_string(base_repo, "full_name", "base repository")
    if base_repository.casefold() != repository.casefold():
        raise EvaluationError("workflow run targets a different base repository")
    if current_head_sha != head_sha:
        print("Skipping stale workflow-policy request for an older pull-request head")
        return 0

    if conclusion != "success":
        StatusPublisher(github_client, repository, head_sha, target_url).publish(
            "failure", "Workflow policy request did not succeed"
        )
        return 1
    return run_pull_request(
        pull,
        repository=repository,
        github_client=github_client,
        target_url=target_url,
    )


def run() -> int:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    target_url = os.environ.get(
        "GITHUB_RUN_URL", "https://github.com/NVIDIA/OpenShell/actions"
    )
    if not event_path or not github_token:
        raise EvaluationError("GITHUB_EVENT_PATH and GITHUB_TOKEN are required")
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"cannot read GitHub event: {exc}") from exc
    event_mapping = _require_mapping(event, "payload")
    github_client = HttpClient(github_token)
    return run_workflow_run(event_mapping, github_client, target_url)


def main() -> int:
    try:
        return run()
    except EvaluationError as exc:
        emit_error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
