# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Preview or explicitly apply one issue/PR classification through the shared helper."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from dataclasses import replace
from pathlib import Path

import label_issue as helper
from label_issue_evidence import expand_evidence
from label_issue_github import GitHubClient
from label_issue_policy import format_report
from labeling_agent_events import item_number
from managed_label_classifier import AgentConfig, ManagedAgents, classify, session_request

ROOT = Path(__file__).resolve().parents[2]
MAX_INPUT_BYTES = 2 * 1024 * 1024
EXPANSION_CONTRACT = """
You may return exactly {"expand_evidence": ["ID", ...]} instead of a final result
when more evidence is needed. Use only snapshot evidence IDs or documented
digest-bound text/source slice IDs. The caller expands them through the helper
and sends all previously delivered packets with the next request.
Collections and metadata are navigation, not substantive evidence. Partial,
truncated, missing and deferred coverage remain explicit; request slices where
needed. Never cite undelivered content. If context remains unavailable, do not
invent a classification. Final output uses the shared result contract directly.
"""


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def instructions():
    """Only checkout-controlled files supply classifier instructions."""
    paths = [
        ".agents/skills/label-issue/SKILL.md",
        ".agents/skills/label-issue/references/result-contract.md",
        "tasks/scripts/label_issue_policy.py",
    ]
    return "\n\n".join(
        f"## {path}\n{(ROOT / path).read_text(encoding='utf-8')}" for path in paths
    ) + EXPANSION_CONTRACT


def evidence_payload(snapshot, packets):
    payload = {
        "packets": packets,
        "manifest": {
            key: snapshot[key]
            for key in (
                "schema_version", "repository", "number", "kind", "snapshot_id",
                "taxonomy", "malformed_classification_labels",
            )
        },
        # Include navigation omitted by the helper's bounded packet paging.
        # Content is supplied exclusively by delivered packets.
        "evidence_index": {
            identity: {key: value for key, value in entry.items() if key != "content"}
            for identity, entry in snapshot["evidence_index"].items()
        },
    }
    if len(json.dumps(payload, ensure_ascii=False).encode()) > MAX_INPUT_BYTES:
        raise ValueError("Evidence exceeds runner input budget; inspect locally")
    return payload


def run(
    repository, number, directory, *, api, trusted_actors, executor=None,
    force=False, apply_saved=False, request_preview=False, config=None,
    timeout=180, max_rounds=4, transport=None, clock=time.monotonic,
):
    """Delegate all eligibility, semantic validation, writes and checkpoints."""
    directory = Path(directory).absolute()
    executions = []
    stage = "prepare"
    report = helper._report({"repository": repository, "number": number}, "error")
    try:
        if not math.isfinite(timeout) or timeout <= 0 or not 1 <= max_rounds <= 8:
            raise ValueError("Positive finite timeout and 1..8 rounds are required")
        if apply_saved and (force or request_preview):
            raise ValueError("Saved application cannot use force or request preview")
        if apply_saved:
            stage = "apply"
            snapshot = read(directory / "manifest.json")
            if (
                snapshot["repository"].casefold() != repository.casefold()
                or snapshot["number"] != number
            ):
                raise ValueError("Saved snapshot does not match the requested item")
            executions = read(directory / "executions.json")
            result = read(directory / "result.json")
            expected = read(directory / "preview.json")
            report = helper.apply(
                snapshot, result, api=api, trusted_actors=trusted_actors,
                executor=executor, expected_preview=expected,
            )
            write(directory / "applied.json", report)
            return report | {"executions": executions, "artifact_directory": str(directory)}

        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if any(directory.iterdir()):
            raise ValueError("Use a new empty output directory for preparation")
        write(directory / "executions.json", executions)
        report = helper.prepare(
            repository, number, directory, api=api,
            trusted_actors=trusted_actors, force=force,
        )
        if report["status"] != "ready" or report.get("classifier_required") is not True:
            return {key: value for key, value in report.items() if key != "snapshot"}
        snapshot = report["snapshot"]
        report = helper._report(snapshot, "error")
        packets = [read(snapshot["packet_path"])]
        stage = "classify"
        if config is None:
            raise ValueError("Configure agent ID, pinned version and environment ID")
        if config.budget_cents < max_rounds:
            raise ValueError("Budget cents must cover at least one cent per round")
        # Bound the sum of all independent session ceilings by the invocation budget.
        session_config = replace(config, budget_cents=config.budget_cents // max_rounds)
        trusted_instructions = instructions()
        deadline = clock() + timeout
        seen_expansions = set()
        for round_number in range(max_rounds):
            request = session_request(
                session_config, trusted_instructions, evidence_payload(snapshot, packets)
            )
            if request_preview:
                write(directory / "request.json", request)
                report.update(status="ready", classifier_required=True,
                              diagnostics=["Request saved; no CMA session or label writes"])
                return report | {"artifact_directory": str(directory)}
            remaining = deadline - clock()
            if remaining <= 0:
                raise ValueError("Runner exceeded the classification deadline")
            if transport is None:
                transport = ManagedAgents(os.environ.get("ANTHROPIC_API_KEY", ""))

            def record_session(session_id, round_id=round_number + 1):
                executions.append({"session_id": session_id, "round": round_id,
                                   "status": "started"})
                write(directory / "executions.json", executions)

            completion = classify(
                transport, request, timeout=remaining, on_session=record_session
            )
            executions[-1]["status"] = "completed"
            write(directory / "executions.json", executions)
            proposal = completion["proposal"]
            write(directory / f"proposal-{round_number + 1}.json", proposal)
            if "expand_evidence" not in proposal:
                write(directory / "result.json", proposal)
                stage = "preview"
                report = helper.preview(snapshot, proposal, api=api, executor=executor)
                write(directory / "preview.json", report)
                return report | {"executions": executions,
                                 "artifact_directory": str(directory)}
            ids = proposal["expand_evidence"]
            if (
                set(proposal) != {"expand_evidence"}
                or not isinstance(ids, list) or not 1 <= len(ids) <= 16
                or any(not isinstance(identity, str) or not identity for identity in ids)
            ):
                raise ValueError("Invalid evidence expansion request")
            if round_number + 1 == max_rounds:
                report.update(status="held",
                              diagnostics=["Evidence expansion round limit reached"])
                return report | {"executions": executions,
                                 "artifact_directory": str(directory)}
            if set(ids) <= seen_expansions:
                raise ValueError("Repeated evidence expansion without progress")
            stage = "expand"
            expand_evidence(snapshot, ids, api=api)
            packet = read(snapshot["packet_path"])
            delivered = packet.get("evidence_index", {}) | packet.get("expanded_evidence", {})
            if any("content" not in delivered.get(identity, {}) for identity in ids):
                report.update(status="prerequisite", missing_prerequisites=[
                    "Requested evidence was deferred by packet bounds; inspect locally or request smaller text slices"
                ])
                return report | {"executions": executions,
                                 "artifact_directory": str(directory)}
            packets.append(packet)
            seen_expansions.update(ids)
            stage = "classify"
    except Exception as exc:
        # Preserve the shared report shape and actionable transport fields.
        if executions and executions[-1]["status"] == "started":
            executions[-1]["status"] = "failed"
            try:
                write(directory / "executions.json", executions)
            except OSError:
                pass  # The durable started record still identifies the session.
        report.pop("snapshot", None)
        report["status"] = (
            "partial" if stage == "apply" and report["status"] in {"applied", "partial", "no-op"}
            else "error"
        )
        helper._failure(report, exc, api)
        report.update(stage=stage, executions=executions,
                      artifact_directory=str(directory))
        return report
    raise RuntimeError("Unreachable classification loop")


def main(argv=None, *, api=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("item", help="One issue/PR number or same-repository GitHub URL")
    parser.add_argument("--repo", default="NVIDIA/OpenShell")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trusted-actor", action="append", required=True)
    parser.add_argument("--executor")
    parser.add_argument("--force", action="store_true",
                        help="Human override of unchanged detection only")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--apply", action="store_true",
                       help="Explicitly authorize the saved exact one-item preview")
    modes.add_argument("--request-preview", action="store_true",
                       help="Save CMA request without invoking the model")
    parser.add_argument("--agent-id")
    parser.add_argument("--agent-version", type=int)
    parser.add_argument("--environment-id")
    parser.add_argument("--budget-cents", type=int, default=25,
                        help="Total ceiling across all classification rounds")
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--max-rounds", type=int, default=4)
    parser.add_argument("--human", action="store_true")
    args = parser.parse_args(argv)
    api = api if api is not None else GitHubClient()
    try:
        number = item_number(args.item, args.repo)
        config = (
            AgentConfig(args.agent_id, args.agent_version, args.environment_id,
                        args.budget_cents)
            if args.agent_id and args.agent_version and args.environment_id else None
        )
        report = run(
            args.repo, number, args.output, api=api,
            trusted_actors=set(args.trusted_actor), executor=args.executor,
            force=args.force, apply_saved=args.apply,
            request_preview=args.request_preview, config=config,
            timeout=args.timeout, max_rounds=args.max_rounds,
        )
    except (ValueError, OSError) as exc:
        report = helper._failure(helper._report({}, "error"), exc, api)
    print(json.dumps(report, ensure_ascii=False))
    if args.human:
        print(format_report(report), file=sys.stderr)
    status = report["status"]
    return (
        0 if status in {"ready", "preview", "applied", "no-op", "unchanged", "skipped"}
        else 2 if status in {"held", "prerequisite", "stale"} else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
