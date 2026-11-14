# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only evidence preparation; fetched sources and inspected facts stay distinct."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
import uuid
from pathlib import Path
from urllib.parse import quote, urlsplit

from check_maintainer_approval import parse_maintainers
from label_accepted_work import (
    CLOSING_ISSUES_QUERY,
    check_issue_accepted_work,
    check_pr_accepted_work,
)
from label_issue_policy import load_taxonomy

LIMIT = 2 * 1024 * 1024
CLOSED_EVENTS_QUERY = """query($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
 repository(owner: $owner, name: $repo) { issue(number: $number) {
  timelineItems(itemTypes: [CLOSED_EVENT, REOPENED_EVENT], last: 100, before: $cursor) {
   nodes { __typename ... on ClosedEvent { id createdAt actor { login }
    closer { __typename ... on PullRequest { number merged mergedAt repository { nameWithOwner } } }
   } ... on ReopenedEvent { id createdAt actor { login } } }
   pageInfo { hasPreviousPage startCursor }
  }
 } }
}"""


def _identity(repository, number):
    if not isinstance(repository, str) or isinstance(number, bool):
        raise ValueError("Invalid repository or issue number")
    try:
        numeric = int(str(number))
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid issue number") from exc
    if repository.startswith("https://"):
        parsed = urlsplit(repository)
        parts = parsed.path.strip("/").split("/")
        if parsed.netloc.lower() != "github.com" or len(parts) not in (2, 4):
            raise ValueError("Invalid repository URL")
        if len(parts) == 4 and (
            parts[2] not in ("issues", "pull") or parts[3] != str(numeric)
        ):
            raise ValueError("Item URL does not match number")
        repository = "/".join(parts[:2])
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or numeric < 1:
        raise ValueError("Invalid repository or issue number")
    return repository, numeric


def _roster(repository, path, revision, api):
    value = api(f"repos/{repository}/contents/{path}?ref={quote(revision, safe='')}")
    if value.get("encoding") != "base64" or value.get("truncated"):
        raise ValueError(f"Incomplete trusted {path}")
    raw = base64.b64decode(value["content"])
    if len(raw) > LIMIT:
        raise ValueError(f"Oversized trusted {path}")
    return raw.decode("utf-8")


def _authority(repository, user, author, maintainers, api):
    login = (user or {}).get("login", "")
    role = "unknown"
    permission = "none"
    if login.lower() in maintainers:
        role, permission = "maintainer", "maintain"
    elif login:
        try:
            permission = api(
                f"repos/{repository}/collaborators/{quote(login, safe='')}/permission"
            )["permission"]
        except subprocess.CalledProcessError as exc:
            if "(HTTP 404)" not in (exc.stderr or ""):
                raise
        if permission in {"write", "maintain", "admin"}:
            role = "maintainer"
        elif login.lower() == author.lower():
            role = "author"
    return {
        "login": login,
        "role": role,
        "permission": permission,
        "is_author": bool(login) and login.lower() == author.lower(),
        "verified": True,
    }


def _closed_event(repository, number, api):
    owner, repo = repository.split("/")
    cursor, seen = None, set()
    for _ in range(100):
        result = api(
            "graphql",
            method="POST",
            data={
                "query": CLOSED_EVENTS_QUERY,
                "variables": {
                    "owner": owner,
                    "repo": repo,
                    "number": number,
                    "cursor": cursor,
                },
            },
        )
        if result.get("errors"):
            raise ValueError("Could not resolve closure provenance")
        connection = result["data"]["repository"]["issue"]["timelineItems"]
        for event in reversed(connection["nodes"]):
            if event["__typename"] == "ClosedEvent":
                return event
        page = connection["pageInfo"]
        if not page["hasPreviousPage"]:
            return None
        cursor = page["startCursor"]
        if not cursor or cursor in seen:
            raise ValueError("Invalid closure-event cursor")
        seen.add(cursor)
    raise ValueError("Closure-event page budget exhausted")


def is_stale_closed(issue: dict, event: dict | None) -> bool:
    """Recognize stale closure from current labels and matching bot/event metadata."""
    actor = issue.get("closed_by") or {}
    login = actor.get("login", "").lower()
    labels = {label["name"] for label in issue.get("labels", [])}
    return bool(
        issue.get("state") == "closed"
        and issue.get("state_reason") == "not_planned"
        and "state:stale" in labels
        and actor.get("type") == "Bot"
        and login in {"github-actions[bot]", "stale[bot]"}
        and issue.get("closed_at")
        and event
        and event.get("__typename") == "ClosedEvent"
        and event.get("createdAt") == issue["closed_at"]
        and (event.get("actor") or {}).get("login", "").lower() == login
    )


def preflight(repository: str, number: int | str, *, api, force: bool = False) -> dict:
    """Fresh acceptance/lifecycle facts; force never relaxes either boundary."""
    del force
    repository, number = _identity(repository, number)
    root = f"repos/{repository}"
    repo = api(root)
    revision = api(f"{root}/commits/{quote(repo['default_branch'], safe='')}")["sha"]
    maintainers_text = _roster(repository, "MAINTAINERS.md", revision, api)
    maintainers = parse_maintainers(maintainers_text)
    issue = api(f"{root}/issues/{number}")
    kind = "pull_request" if "pull_request" in issue else "issue"
    item = api(f"{root}/pulls/{number}") if kind == "pull_request" else issue
    accepted = (
        check_pr_accepted_work(repository, item, maintainers, api=api)
        if kind == "pull_request"
        else check_issue_accepted_work(repository, issue, maintainers, api=api)
    )
    lifecycle, reason, event, authority = "eligible", "Open work", None, None
    if kind == "pull_request" and (item.get("merged_at") or item.get("merged")):
        lifecycle, reason = (
            "excluded",
            "Pull request merged (including reverted merges)",
        )
    elif issue.get("state") == "closed":
        lifecycle, reason = (
            "hold",
            "Closed item requires evidence-backed human disposition",
        )
        if kind == "issue" and issue.get("state_reason") == "completed":
            lifecycle, reason = "excluded", "Issue completed"
        elif kind == "issue":
            event = _closed_event(repository, number, api)
            closer = (event or {}).get("closer") or {}
            if closer.get("__typename") == "PullRequest" and closer.get("merged"):
                lifecycle, reason = (
                    "excluded",
                    "Issue resolved by merged closing pull request",
                )
            else:
                actor = issue.get("closed_by") or (event or {}).get("actor") or {}
                author = (issue.get("user") or {}).get("login", "")
                authority = _authority(repository, actor, author, maintainers, api)
                if (
                    issue.get("state_reason") in {"not_planned", "duplicate"}
                    and actor.get("type") != "Bot"
                    and authority["role"] == "maintainer"
                ):
                    lifecycle, reason = "excluded", "Deliberate maintainer closure"
                elif is_stale_closed(issue, event):
                    lifecycle, reason = (
                        "eligible",
                        "Verified stale-bot closure alone is not resolution",
                    )
    return {
        "repository": repository,
        "number": number,
        "kind": kind,
        "item_id": issue["node_id"],
        "revision": revision,
        "item": item,
        "issue": issue,
        "maintainers": sorted(maintainers),
        "maintainers_text": maintainers_text,
        "closure_event": event,
        "closure_authority": authority,
        "eligibility": {"accepted": accepted, "lifecycle": lifecycle, "reason": reason},
    }


def _semantic(kind, value):
    """Substantive provider facts; raw artifacts retain all other context and bounds."""
    if isinstance(value, list):
        return [_semantic(kind, entry) for entry in value]
    if not isinstance(value, dict):
        return value
    fields = {
        "user": ("login", "id", "node_id", "type"),
        "label": ("name", "id", "node_id", "description", "assessment"),
        "body": ("title", "body"),
        "item": (
            "repository",
            "number",
            "item_id",
            "title",
            "body",
            "state",
            "state_reason",
            "closed_at",
            "merged_at",
            "merged",
            "user",
            "assignees",
            "draft",
            "head",
            "base",
            "changed_files",
        ),
        "patch": (
            "filename",
            "previous_filename",
            "sha",
            "status",
            "additions",
            "deletions",
            "changes",
            "patch",
            "truncated",
            "patch_truncated",
        ),
        "comment": (
            "id",
            "node_id",
            "body",
            "user",
            "author_association",
            "created_at",
            "updated_at",
        ),
        "review": (
            "id",
            "node_id",
            "body",
            "user",
            "author_association",
            "state",
            "submitted_at",
            "updated_at",
            "commit_id",
        ),
        "review_comment": (
            "id",
            "node_id",
            "body",
            "user",
            "author_association",
            "created_at",
            "updated_at",
            "diff_hunk",
            "path",
            "line",
            "start_line",
            "side",
            "start_side",
            "position",
            "original_position",
            "original_line",
            "original_start_line",
            "commit_id",
            "original_commit_id",
            "in_reply_to_id",
            "subject_type",
        ),
        "lifecycle": ("__typename", "id", "createdAt", "actor", "closer"),
    }
    linked = kind == "linked_issue"
    kind = {"linked_issue": "item", "relevant_timeline": "lifecycle"}.get(kind, kind)
    result = {
        key: copy.deepcopy(value[key])
        for key in fields.get(kind, value)
        if key in value
    }
    if linked and "labels" in value:
        result["labels"] = copy.deepcopy(value["labels"])
    for key in ("user", "actor"):
        if key in result:
            result[key] = _semantic("user", result[key])
    if "assignees" in result:
        result["assignees"] = _semantic("user", result["assignees"])
    for key in ("head", "base"):
        if key in result and isinstance(result[key], dict):
            result[key] = {
                k: result[key][k] for k in ("sha", "ref") if k in result[key]
            }
    return result


def _artifact(kind, content, *, inspected=False, coverage="complete", **extra):
    raw_text = content.get("body") if isinstance(content, dict) else None
    encoded = json.dumps(content, ensure_ascii=False, sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    semantic_digest = hashlib.sha256(
        json.dumps(_semantic(kind, content), ensure_ascii=False, sort_keys=True).encode(
            "utf-8"
        )
    ).hexdigest()
    if len(encoded) > LIMIT - 4096:
        # Slice characters, not encoded JSON bytes, then re-encode valid JSON.
        text = encoded.decode("utf-8")
        low, high = 0, min(len(text), LIMIT)
        while low < high:
            middle = (low + high + 1) // 2
            if (
                len(json.dumps(text[:middle], ensure_ascii=False).encode())
                <= LIMIT - 4096
            ):
                low = middle
            else:
                high = middle - 1
        content, coverage = text[:low], "truncated"
    return {
        "kind": kind,
        "content": content,
        "inspected": inspected,
        "coverage": coverage,
        "source_digest": digest,
        "source_bytes": len(encoded),
        "semantic_digest": semantic_digest,
        **({"_raw_text": raw_text} if isinstance(raw_text, str) else {}),
        **extra,
    }


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _text_parts(directory, prefix, text):
    """Local content chunks have valid UTF-8 and individually bounded delivery."""
    raw = text.encode("utf-8")
    paths, offset = [], 0
    while offset < len(raw):
        end = min(offset + LIMIT, len(raw))
        while end < len(raw) and raw[end] & 0xC0 == 0x80:
            end -= 1
        path = directory / f"{prefix}-{len(paths)}.txt"
        path.write_bytes(raw[offset:end])
        paths.append(str(path))
        offset = end
    return paths


def _write_packet(snapshot, preferred_ids):
    directory, index = Path(snapshot["_directory"]), snapshot["evidence_index"]
    packet = {
        key: snapshot[key]
        for key in (
            "schema_version",
            "repository",
            "number",
            "kind",
            "snapshot_id",
            "item_id",
            "eligibility",
        )
    }
    sections = {
        key: snapshot[key] for key in ("existing_labels", "head", "changed_paths")
    }
    sections["scopes"] = {key: snapshot["taxonomy"][key] for key in ("areas", "topics")}
    for key, value in sections.items():
        if len(_json_bytes({**packet, key: value})) < LIMIT // 2:
            packet[key] = value
        else:
            encoded = _json_bytes(value)
            packet[key + "_ref"] = {
                "parts": _text_parts(directory, "packet-" + key, encoded.decode()),
                "digest": hashlib.sha256(encoded).hexdigest(),
                "coverage": "deferred",
            }
    metadata = {
        artifact_id: {
            **{key: value for key, value in entry.items() if key != "content"},
            "content_deferred": True,
        }
        for artifact_id, entry in index.items()
    }
    pending_pages = []
    if len(_json_bytes({**packet, "evidence_index": metadata})) <= LIMIT // 2:
        packet["evidence_index"] = metadata
        packet["index_coverage"] = "complete"
    else:
        # Only the index is paged. The main packet lists every bounded page;
        # explicit expansions are delivered separately below.
        pages, page, page_bytes = [], {}, 2
        for artifact_id, entry in metadata.items():
            entry_bytes = len(_json_bytes(artifact_id)) + 1 + len(_json_bytes(entry))
            if entry_bytes + 2 > LIMIT:
                raise ValueError("Evidence metadata entry exceeds packet bound")
            if page_bytes + entry_bytes + bool(page) > LIMIT:
                path = directory / f"packet-index-{len(pages)}.json"
                pending_pages.append((path, page))
                pages.append(str(path))
                page, page_bytes = {}, 2
            page_bytes += entry_bytes + bool(page)
            page[artifact_id] = entry
        if page:
            path = directory / f"packet-index-{len(pages)}.json"
            pending_pages.append((path, page))
            pages.append(str(path))
        packet.update(evidence_index={}, index_pages=pages, index_coverage="paged")
    ordered = list(dict.fromkeys([*preferred_ids, "body", *index]))
    for artifact_id in ordered:
        entry = index.get(artifact_id)
        if not entry or not (
            entry["inspected"]
            or artifact_id in preferred_ids
            or entry["kind"] in {"body", "reconciliation", "linked_issue", "lifecycle"}
        ):
            continue
        target = (
            packet["evidence_index"]
            if artifact_id in packet["evidence_index"]
            else packet.setdefault("expanded_evidence", {})
        )
        prior = target.get(artifact_id)
        delivered = {**metadata[artifact_id], "content": entry["content"]}
        delivered.pop("content_deferred", None)
        target[artifact_id] = delivered
        if len(_json_bytes(packet)) > LIMIT:
            if prior is None:
                target.pop(artifact_id)
            else:
                target[artifact_id] = prior
        else:
            entry["inspected"] = delivered["inspected"] = metadata[artifact_id][
                "inspected"
            ] = True
    encoded = _json_bytes(packet)
    if len(encoded) > LIMIT:
        raise ValueError("Packet reference metadata exceeds delivery bound")
    for path, page in pending_pages:
        page_bytes = _json_bytes(page)
        if len(page_bytes) > LIMIT:
            raise ValueError("Evidence metadata page exceeds delivery bound")
        path.write_bytes(page_bytes)
    Path(snapshot["packet_path"]).write_bytes(encoded)


def _persist(snapshot, preferred_ids=()):
    directory = Path(snapshot["_directory"])
    artifacts = directory / "artifacts"
    artifacts.mkdir(exist_ok=True)
    for artifact_id, entry in snapshot["evidence_index"].items():
        raw_text = entry.pop("_raw_text", None)
        if raw_text is not None:
            entry["text_source"] = {
                "characters": len(raw_text),
                "text_digest": hashlib.sha256(raw_text.encode()).hexdigest(),
                "parts": _text_parts(artifacts, entry["source_digest"], raw_text),
            }
        path = artifacts / (hashlib.sha256(artifact_id.encode()).hexdigest() + ".json")
        entry["artifact_path"] = str(path)
        path.write_bytes(_json_bytes(entry["content"]))
    snapshot["packet_path"] = str(directory / "packet.json")
    _write_packet(snapshot, preferred_ids)
    (directory / "manifest.json").write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _one_edit(left, right):
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        diff = [i for i, (a, b) in enumerate(zip(left, right, strict=False)) if a != b]
        return len(diff) == 1 or (
            len(diff) == 2
            and diff[1] == diff[0] + 1
            and left[diff[0]] == right[diff[1]]
            and left[diff[1]] == right[diff[0]]
        )
    shorter, longer = sorted((left, right), key=len)
    return any(longer[:i] + longer[i + 1 :] == shorter for i in range(len(longer)))


def _malformed(labels, taxonomy):
    found = []
    for label in labels:
        namespace, separator, suffix = label.partition(":")
        if not separator or namespace in {"area", "topic", "retired"}:
            continue
        for family, canonical in (
            ("area", taxonomy["areas"]),
            ("topic", taxonomy["topics"]),
        ):
            if _one_edit(namespace, family) and f"{family}:{suffix}" in canonical:
                found.append(label)
    return sorted(set(found))


def _linked_issues(repository, number, api):
    owner, repo = repository.split("/")
    cursor, seen, found = None, set(), []
    for _ in range(100):
        response = api(
            "graphql",
            method="POST",
            data={
                "query": CLOSING_ISSUES_QUERY,
                "variables": {
                    "owner": owner,
                    "repo": repo,
                    "number": number,
                    "cursor": cursor,
                },
            },
        )
        if response.get("errors"):
            raise ValueError("Could not load closing issues")
        connection = response["data"]["repository"]["pullRequest"][
            "closingIssuesReferences"
        ]
        for reference in connection["nodes"]:
            source, linked_number = (
                reference["repository"]["nameWithOwner"],
                reference["number"],
            )
            # Native references may be cross-repository: record identity, but
            # never treat them as accepted-work authorization for this repository.
            source, linked_number = _identity(source, linked_number)
            issue = api(f"repos/{source}/issues/{linked_number}")
            if "pull_request" in issue:
                raise ValueError("Closing issue reference resolved to a pull request")
            labels = api(
                f"repos/{source}/issues/{linked_number}/labels?per_page=100", pages=True
            )
            found.append(
                {
                    "repository": source,
                    "number": linked_number,
                    "item_id": issue["node_id"],
                    "title": issue.get("title"),
                    "body": issue.get("body"),
                    "state": issue["state"],
                    "state_reason": issue.get("state_reason"),
                    "user": issue.get("user"),
                    "assignees": issue.get("assignees", []),
                    "labels": sorted(x["name"] for x in labels),
                }
            )
        page = connection["pageInfo"]
        if not page["hasNextPage"]:
            return found
        cursor = page["endCursor"]
        if not cursor or cursor in seen:
            raise ValueError("Invalid closing-issue cursor")
        seen.add(cursor)
    raise ValueError("Closing-issue page budget exhausted")


def prepare_snapshot(
    repository: str,
    number: int | str,
    directory: Path,
    *,
    api,
    assessment_labels=frozenset(),
) -> dict:
    """Create a local packet with a separately reviewed assessment allowlist."""
    facts = preflight(repository, number, api=api)
    repository, number = facts["repository"], facts["number"]
    root = f"repos/{repository}"
    roster = _roster(repository, "REVIEWERS.md", facts["revision"], api)
    watchers = _roster(repository, "WATCHERS.md", facts["revision"], api)
    contribution_policy = _roster(repository, "CONTRIBUTING.md", facts["revision"], api)
    definitions = copy.deepcopy(api(f"{root}/labels?per_page=100", pages=True))
    for definition in definitions:
        definition.pop("assessment", None)
        if definition["name"] in assessment_labels:
            definition["assessment"] = True
    taxonomy = load_taxonomy(roster, definitions)
    labels = sorted(
        x["name"]
        for x in api(f"{root}/issues/{number}/labels?per_page=100", pages=True)
    )
    item = facts["item"]
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=True)
    index = {
        "body": _artifact(
            "body", {"title": item.get("title"), "body": item.get("body")}
        ),
        "labels": _artifact("reconciliation", labels),
    }
    routes = {
        "comments": f"issues/{number}/comments",
        "timeline": f"issues/{number}/timeline",
    }
    if facts["kind"] == "pull_request":
        routes.update(
            files=f"pulls/{number}/files",
            reviews=f"pulls/{number}/reviews",
            review_comments=f"pulls/{number}/comments",
        )
    for key, route in routes.items():
        index[key] = _artifact(
            key,
            None,
            inspected=False,
            coverage="not_inspected",
            endpoint=f"{root}/{route}?per_page=100",
        )
    linked = (
        _linked_issues(repository, number, api)
        if facts["kind"] == "pull_request"
        else []
    )
    for issue in linked:
        index[f"issue:{issue['repository']}#{issue['number']}"] = _artifact(
            "linked_issue", issue
        )
    policy_text = json.dumps(
        {
            "protocol": 1,
            "maintainers": facts["maintainers_text"],
            "reviewers": roster,
            "watchers": watchers,
            "contribution_policy": contribution_policy,
        },
        sort_keys=True,
    )
    snapshot = {
        "schema_version": 1,
        "repository": repository,
        "number": number,
        "kind": facts["kind"],
        "snapshot_id": str(uuid.uuid4()),
        "item_id": facts["item_id"],
        "policy_revision": facts["revision"],
        "policy_version": hashlib.sha256(policy_text.encode()).hexdigest(),
        "taxonomy": taxonomy,
        "existing_labels": labels,
        "trusted_maintainers": facts["maintainers"],
        "malformed_classification_labels": _malformed(labels, taxonomy),
        "eligibility": facts["eligibility"],
        "head": (item.get("head") or {}).get("sha"),
        "changed_paths": [],
        "linked_closing_issues": linked,
        "item_material": _semantic("item", item),
        "lifecycle_facts": {
            "closure_event": facts["closure_event"],
            "closure_authority": facts["closure_authority"],
        },
        "evidence_index": index,
        "_directory": str(directory),
    }
    if facts["closure_event"]:
        index["closure"] = _artifact(
            "lifecycle",
            facts["closure_event"],
            actor_authority=facts["closure_authority"],
        )
    # Open items can contain human abandonment or rejection statements.
    _refresh_collection(snapshot, "comments", api)
    index["comments"]["inspected"] = False
    author = (facts["issue"].get("user") or {}).get("login", "").lower()
    authorities = {}
    for _artifact_id, entry in index.items():
        if entry["kind"] != "comment":
            continue
        user = entry.get("source_user") or {}
        login = user.get("login", "").lower()
        if (
            login == author
            or login in facts["maintainers"]
            or entry.get("source_association") in {"OWNER", "MEMBER", "COLLABORATOR"}
        ):
            if login not in authorities:
                authorities[login] = _authority(
                    repository, user, author, set(facts["maintainers"]), api
                )
            entry["actor_authority"] = copy.deepcopy(authorities[login])
    if facts["kind"] == "pull_request":
        _refresh_collection(snapshot, "files", api)
        index["files"]["inspected"] = False
    _persist(snapshot)
    return snapshot


def _patch_coverage(entry):
    patch = entry.get("patch")
    if (
        not isinstance(patch, str)
        or not patch
        or not re.search(r"^@@ ", patch, flags=re.M)
        or entry.get("truncated")
        or entry.get("patch_truncated")
    ):
        return "partial"
    plus = minus = 0
    for line in patch.splitlines():
        if line.startswith("+"):
            plus += 1
        elif line.startswith("-"):
            minus += 1
    if plus != entry.get("additions") or minus != entry.get("deletions"):
        return "partial"
    # Changed-line counts detect omissions even when the provider sets no flag.
    for old_count, new_count, body in re.findall(
        r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@[^\n]*\n(.*?)(?=\n@@|\Z)", patch, re.S
    ):
        lines = body.splitlines()
        old = sum(line.startswith(("-", " ")) for line in lines)
        new = sum(line.startswith(("+", " ")) for line in lines)
        if old != int(old_count or 1) or new != int(new_count or 1):
            return "partial"
    return "complete"


def _source_slice(snapshot, artifact_id, api):
    match = re.fullmatch(r"source:(.+):(\d+):(\d+)", artifact_id)
    if not match or snapshot["kind"] != "pull_request" or not snapshot.get("head"):
        raise ValueError("Invalid focused source request")
    path, start, end = match[1], int(match[2]), int(match[3])
    if (
        path.startswith("/")
        or any(part in {".", "..", ""} for part in path.split("/"))
        or path not in snapshot["changed_paths"]
        or not 1 <= start <= end
    ):
        raise ValueError("Source slices must name a changed path and valid lines")
    value = api(
        f"repos/{snapshot['repository']}/contents/{quote(path, safe='/')}?ref={quote(snapshot['head'], safe='')}"
    )
    if value.get("encoding") != "base64" or value.get("truncated"):
        raise ValueError(
            "Provider omitted requested source; request a smaller source through another supported endpoint"
        )
    text = base64.b64decode(value["content"]).decode("utf-8")
    content = "".join(text.splitlines(keepends=True)[start - 1 : end])
    return _artifact(
        "source",
        content,
        coverage="slice",
        path=path,
        start=start,
        end=end,
        revision=snapshot["head"],
    )


def _text_slice(snapshot, artifact_id):
    match = re.fullmatch(r"text:(.+):([0-9a-f]{64}):(\d+):(\d+)", artifact_id)
    if not match:
        raise ValueError("Invalid text slice request")
    source_id, digest, start, end = match[1], match[2], int(match[3]), int(match[4])
    source = snapshot["evidence_index"].get(source_id)
    if not source or source["source_digest"] != digest or "text_source" not in source:
        raise ValueError("Text source identity/digest changed or is unavailable")
    metadata = source["text_source"]
    if not 0 <= start < end <= metadata["characters"]:
        raise ValueError("Text slice range is outside the source")
    text = "".join(
        Path(path).read_bytes().decode("utf-8") for path in metadata["parts"]
    )
    if hashlib.sha256(text.encode()).hexdigest() != metadata["text_digest"]:
        raise ValueError("Local text source digest mismatch")
    return _artifact(
        "text_slice",
        text[start:end],
        coverage="slice",
        parent_id=source_id,
        parent_digest=digest,
        start=start,
        end=end,
    )


def _verify_head(snapshot, api):
    current = api(f"repos/{snapshot['repository']}/pulls/{snapshot['number']}")
    if (current.get("head") or {}).get("sha") != snapshot["head"] or (
        current.get("base") or {}
    ).get("sha") != snapshot["item_material"].get("base", {}).get("sha"):
        snapshot["stale"] = True
        raise ValueError("PR head/base moved; rebuild the evidence snapshot")


def _refresh_collection(snapshot, artifact_id, api):
    index = snapshot["evidence_index"]
    artifact = index[artifact_id]
    endpoint = artifact["endpoint"]
    if artifact_id == "files":
        _verify_head(snapshot, api)
    content = api(endpoint, pages=True)
    if artifact_id == "files":
        _verify_head(snapshot, api)
    if not isinstance(content, list):
        raise ValueError("Collection must be a paginated list")
    coverage, replacements = "complete", {}
    authorities = {}
    prefixes = {
        "comments": ("comment", "comment"),
        "reviews": ("review", "review"),
        "review_comments": ("review-comment", "review_comment"),
        "timeline": ("event", "timeline_event"),
    }
    for entry in content:
        if artifact_id == "files":
            source_id, kind = "patch:" + entry["filename"], "patch"
            source_coverage = _patch_coverage(entry)
        else:
            prefix, kind = prefixes[artifact_id]
            if entry.get("id") is None:
                raise ValueError("Evidence source lacks stable identity")
            source_id, source_coverage = f"{prefix}:{entry['id']}", "complete"
        if source_id in replacements:
            raise ValueError("Duplicate evidence source identity")
        candidate = _artifact(
            kind,
            entry,
            coverage=source_coverage,
            source_user={
                key: value
                for key, value in (entry.get("user") or {}).items()
                if key in {"login", "type"}
            },
            source_association=entry.get("author_association"),
        )
        previous = index.get(source_id)
        if previous and previous["source_digest"] == candidate["source_digest"]:
            candidate = copy.deepcopy(previous)
            if candidate.get("actor_authority"):
                author = (snapshot["item_material"].get("user") or {}).get("login", "")
                login = (candidate.get("source_user") or {}).get("login", "").casefold()
                if login not in authorities:
                    authorities[login] = _authority(
                        snapshot["repository"],
                        candidate.get("source_user"),
                        author,
                        set(snapshot["trusted_maintainers"]),
                        api,
                    )
                candidate["actor_authority"] = copy.deepcopy(authorities[login])
        replacements[source_id] = candidate
        if candidate["coverage"] != "complete":
            coverage = "partial"
    old_members = set(artifact.get("members", artifact["content"] or []))
    invalidated = {
        source_id
        for source_id in old_members
        if source_id not in replacements
        or index[source_id]["source_digest"] != replacements[source_id]["source_digest"]
    }
    for source_id in old_members - replacements.keys():
        index.pop(source_id, None)
    for source_id, entry in list(index.items()):
        if entry.get("parent_id") in invalidated:
            index.pop(source_id)
    index.update(replacements)
    if artifact_id == "files":
        snapshot["changed_paths"] = [entry["filename"] for entry in content]
        if len(content) != snapshot["item_material"].get("changed_files"):
            coverage = "incomplete"
    members = list(replacements)
    artifact.update(
        _artifact(
            artifact["kind"],
            members,
            coverage=coverage,
            endpoint=endpoint,
            members=members,
        )
    )


def expand_evidence(snapshot: dict, evidence_ids: list[str], *, api) -> dict:
    """Expand stable sources or bounded digest-bound text/source slices."""
    index = snapshot["evidence_index"]
    authorities = {}
    for artifact_id in evidence_ids:
        if artifact_id.startswith("text:"):
            index[artifact_id] = _text_slice(snapshot, artifact_id)
            continue
        if artifact_id.startswith("source:"):
            index[artifact_id] = _source_slice(snapshot, artifact_id, api)
            continue
        if artifact_id not in index:
            raise ValueError(f"Unknown evidence ID: {artifact_id}")
        artifact = index[artifact_id]
        if not artifact.get("endpoint"):
            if artifact.get("kind") in {"comment", "review", "review_comment"}:
                author = (snapshot["item_material"].get("user") or {}).get("login", "")
                login = (artifact.get("source_user") or {}).get("login", "").casefold()
                if login not in authorities:
                    authorities[login] = _authority(
                        snapshot["repository"],
                        artifact.get("source_user"),
                        author,
                        set(snapshot["trusted_maintainers"]),
                        api,
                    )
                authority = copy.deepcopy(authorities[login])
                artifact["actor_authority"] = authority
            continue
        try:
            _refresh_collection(snapshot, artifact_id, api)
        except Exception:
            artifact.update(inspected=False, coverage="incomplete")
            _persist(snapshot)
            raise
    _persist(snapshot, evidence_ids)
    return snapshot


def material_state(snapshot: dict) -> dict:
    """Project substantive facts and source digests, excluding local paths and updatedAt."""
    keys = (
        "repository",
        "number",
        "kind",
        "item_id",
        "policy_version",
        "taxonomy",
        "existing_labels",
        "eligibility",
        "head",
        "changed_paths",
        "item_material",
        "linked_closing_issues",
        "lifecycle_facts",
        "malformed_classification_labels",
        "stale",
    )
    result = copy.deepcopy({key: snapshot[key] for key in keys if key in snapshot})
    result["taxonomy"]["definitions"] = {
        name: _semantic("label", definition)
        for name, definition in result["taxonomy"]["definitions"].items()
    }
    result["linked_closing_issues"] = _semantic(
        "linked_issue", result["linked_closing_issues"]
    )
    result["lifecycle_facts"]["closure_event"] = _semantic(
        "lifecycle", result["lifecycle_facts"]["closure_event"]
    )
    result["evidence_index"] = {}
    for artifact_id, entry in snapshot.get("evidence_index", {}).items():
        result["evidence_index"][artifact_id] = {
            key: copy.deepcopy(value)
            for key, value in entry.items()
            if key not in {"artifact_path", "endpoint", "text_source"}
            and (key != "content" or entry.get("inspected"))
        }
        if "text_source" in entry:
            result["evidence_index"][artifact_id]["text_source"] = {
                key: value
                for key, value in entry["text_source"].items()
                if key != "parts"
            }
    return result
