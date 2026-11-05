# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run an advisory branch or cumulative release compatibility review with Codex."""

import argparse
import asyncio
import json
import os
import re
import subprocess
import tempfile
import time
from contextlib import aclosing
from importlib.metadata import version
from pathlib import Path

# Installed only in the review workflow's isolated Python environment.
import openai_codex  # ty: ignore[unresolved-import]
from check_proto_compatibility import git, train_policy
from codex_compatibility_report import validate_review, write_report
from openai_codex.generated.v2_all import (  # ty: ignore[unresolved-import]
    AgentMessageThreadItem,
    ErrorNotification,
    ItemCompletedNotification,
    MessagePhase,
    TurnCompletedNotification,
)

ASSETS = Path(__file__).resolve().parents[2] / ".github" / "prompts"
MODEL = "openai/openai/gpt-6.1-sol"
ENDPOINT = "https://inference-api.nvidia.com/v1"

# Error messages/details may contain source, tool output, or credentials. Publish
# only protocol-defined states, never arbitrary strings from the SDK or model.
ERROR_CODES = frozenset(
    {
        "contextWindowExceeded",
        "sessionBudgetExceeded",
        "usageLimitExceeded",
        "rateLimitExceeded",
        "flexUnavailable",
        "serverOverloaded",
        "cyberPolicy",
        "misalignmentPolicyViolation",
        "tooManyDenials",
        "internalServerError",
        "unauthorized",
        "badRequest",
        "threadRollbackFailed",
        "sandboxError",
        "other",
        "httpConnectionFailed",
        "responseStreamConnectionFailed",
        "responseStreamDisconnected",
        "responseTooManyFailedAttempts",
        "activeTurnNotSteerable",
    }
)


def public_turn_error(error) -> dict:
    """Extract only allowlisted protocol fields, not message/additionalDetails."""
    info = error.codex_error_info
    value = info.model_dump(mode="json", by_alias=True) if info is not None else None
    code = value if isinstance(value, str) else None
    status = None
    if isinstance(value, dict) and len(value) == 1:
        code, details = next(iter(value.items()))
        if code in ERROR_CODES and isinstance(details, dict):
            status = details.get("httpStatusCode", details.get("http_status_code"))
    return {
        "code": code if code in ERROR_CODES else "unknown",
        "http_status": status if type(status) is int and 100 <= status <= 599 else None,
    }


async def collect_review(thread, prompt: str, schema: dict, diagnostics: dict) -> str:
    """Consume the public turn stream before the SDK erases structured errors."""
    diagnostics["phase"] = "turn_start"
    turn = await thread.turn(prompt, output_schema=schema)
    diagnostics["phase"] = "turn_stream"
    completed = None
    final_response = None
    fallback_response = None
    async with aclosing(turn.stream()) as stream:
        async for event in stream:
            payload = event.payload
            if isinstance(payload, ErrorNotification):
                diagnostics["error_events"] += 1
                diagnostics["retry_events"] += int(payload.will_retry)
                diagnostics["last_error"] = public_turn_error(payload.error)
            elif isinstance(payload, TurnCompletedNotification):
                completed = payload.turn
                status = completed.status.value
                diagnostics["turn_status"] = (
                    status
                    if status in ("completed", "failed", "interrupted", "inProgress")
                    else "unknown"
                )
                if completed.error is not None:
                    diagnostics["final_error"] = public_turn_error(completed.error)
            elif isinstance(payload, ItemCompletedNotification):
                item = payload.item.root
                if isinstance(item, AgentMessageThreadItem):
                    if item.phase == MessagePhase.final_answer:
                        final_response = item.text
                    elif item.phase is None:
                        fallback_response = item.text
    if completed is None:
        diagnostics["reason"] = "missing_completion"
        raise ValueError("Codex turn ended without a completion event.")
    if completed.status.value != "completed":
        diagnostics["reason"] = "unsuccessful_turn"
        raise ValueError("Codex did not complete the compatibility review.")
    response = final_response if final_response is not None else fallback_response
    if not response:
        diagnostics["reason"] = "missing_final_response"
        raise ValueError("Codex completed without a final compatibility report.")
    return response


def resolve_candidate(tag: str, expected_sha: str) -> dict:
    if not re.fullmatch(r"v0\.\d+\.\d+(?:-pre\.\d+)?", tag):
        raise ValueError("Compatibility review requires a tagged 0.x release.")
    candidate = git(
        "rev-parse", "--verify", "--end-of-options", f"refs/tags/{tag}^{{commit}}"
    )
    if expected_sha and candidate != expected_sha:
        raise ValueError("Candidate tag does not match the qualification source SHA.")
    baseline, train, allows_breaks = train_policy(candidate, tag)
    return {
        "candidate_tag": tag,
        "candidate_sha": candidate,
        "source_sha": candidate,
        "baseline_tag": baseline,
        "baseline_sha": git(
            "rev-parse", "--verify", f"refs/tags/{baseline}^{{commit}}"
        ),
        "train": train,
        "allows_breaks": allows_breaks,
    }


def resolve_branch(base_ref: str, source_sha: str, pr_number: int) -> dict:
    if not re.fullmatch(r"[a-fA-F0-9]{40}", source_sha):
        raise ValueError("Branch review requires the exact source commit SHA.")
    baseline = git(
        "rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}"
    )
    candidate = git("rev-parse", "--verify", f"{source_sha}^{{commit}}")
    _, train, allows_breaks = train_policy(baseline, None)
    merged = git("merge-tree", "--write-tree", baseline, candidate).splitlines()[0]
    return {
        "candidate_tag": f"PR #{pr_number}" if pr_number else candidate[:12],
        "candidate_sha": merged,
        "source_sha": candidate,
        "baseline_tag": base_ref,
        "baseline_sha": baseline,
        "train": train,
        "allows_breaks": allows_breaks,
        "mode": "branch",
    }


async def invoke_codex(context: dict, directory: Path, diagnostics: dict) -> dict:
    # Git objects expose both revisions without loading candidate-side agent
    # instructions, configuration, skills, or hooks into the review workspace.
    diagnostics["phase"] = "clone_source"
    subprocess.run(
        [
            "git",
            "clone",
            "--bare",
            "--no-hardlinks",
            "--quiet",
            ".",
            str(directory / "source.git"),
        ],
        check=True,
        capture_output=True,
    )
    settings = (
        "allow_login_shell=false",
        'default_permissions="compatibility"',
        'permissions.compatibility.extends=":read-only"',
        "permissions.compatibility.network.enabled=true",
        'permissions.compatibility.network.domains={"api.github.com"="allow"}',
        "permissions.compatibility.network.allow_upstream_proxy=false",
        "permissions.compatibility.network.enable_socks5=false",
        "permissions.compatibility.network.enable_socks5_udp=false",
        "features.network_proxy=true",
        'model_providers.nvidia.name="NVIDIA Inference"',
        f'model_providers.nvidia.base_url="{ENDPOINT}"',
        'model_providers.nvidia.env_key="NVIDIA_INFERENCE_API_KEY"',
        'model_providers.nvidia.wire_api="responses"',
        "model_providers.nvidia.supports_websockets=false",
        'model_reasoning_effort="high"',
        'web_search="disabled"',
        "project_doc_max_bytes=0",
        "features.hooks=false",
        "features.plugins=false",
        "features.multi_agent=false",
        "features.multi_agent_v2=false",
        'shell_environment_policy.inherit="all"',
        "shell_environment_policy.ignore_default_excludes=true",
        'shell_environment_policy.filters={PATH="include", HOME="include", GH_TOKEN="include", '
        'SSL_CERT_FILE="include", SSL_CERT_DIR="include"}',
    )
    diagnostics["phase"] = "load_prompt"
    prompt = (ASSETS / "compatibility-review.md").read_text()
    prompt += "\nReview context:\n" + json.dumps(context)
    schema = json.loads((ASSETS / "compatibility-review.schema.json").read_text())
    codex = openai_codex.AsyncCodex(
        openai_codex.CodexConfig(cwd=str(directory), config_overrides=settings)
    )
    # Retain structured failure states, but never SDK messages or transcripts.
    try:
        async with asyncio.timeout(1800):
            diagnostics["phase"] = "thread_start"
            thread = await codex.thread_start(
                cwd=str(directory),
                model=MODEL,
                model_provider="nvidia",
                approval_mode=openai_codex.ApprovalMode.deny_all,
                ephemeral=True,
            )
            response = await collect_review(thread, prompt, schema, diagnostics)
    except (openai_codex.CodexError, RuntimeError, ValueError) as error:
        diagnostics["error_type"] = type(error).__name__
        if isinstance(error, openai_codex.JsonRpcError) and type(error.code) is int:
            diagnostics["rpc_code"] = error.code
        raise ValueError(
            f"Codex SDK review failed ({type(error).__name__}); no assessment is available."
        ) from None
    finally:
        await codex.close()
    diagnostics["phase"] = "decode_report"
    review = json.loads(response)
    diagnostics["phase"] = "validate_report"
    validate_review(review)
    return review


def run_review(
    tag: str, expected_sha: str, output: Path, base_ref: str, pr_number: int
) -> dict:
    started = time.monotonic()
    diagnostics = {
        "phase": "resolve_context",
        "error_events": 0,
        "retry_events": 0,
    }
    result = {
        "schema_version": 3,
        "advisory": True,
        "status": "error",
        "context": {},
        "review": None,
        "error": "",
        "diagnostics": diagnostics,
        "model": MODEL,
        "reasoning_effort": "high",
        "codex_version": "",
        "codex_sdk_version": "",
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    try:
        result["context"] = (
            resolve_branch(base_ref, expected_sha, pr_number)
            if base_ref
            else resolve_candidate(tag, expected_sha)
        )
        diagnostics["phase"] = "credentials"
        if not os.environ.get("NVIDIA_INFERENCE_API_KEY"):
            raise ValueError("NVIDIA inference credential is missing.")
        diagnostics["phase"] = "tool_versions"
        result["codex_version"] = version("openai-codex-cli-bin")
        result["codex_sdk_version"] = version("openai-codex")
        result["context"]["repository"] = os.environ.get("GITHUB_REPOSITORY", "")
        result["context"]["pr_number"] = pr_number
        with tempfile.TemporaryDirectory(
            prefix="openshell-compatibility-"
        ) as temporary:
            result["review"] = asyncio.run(
                invoke_codex(result["context"], Path(temporary), diagnostics)
            )
        result["status"] = (
            "incomplete" if result["review"]["unreviewed_surfaces"] else "complete"
        )
        diagnostics["phase"] = "complete"
    except TimeoutError:
        diagnostics["error_type"] = "TimeoutError"
        diagnostics["reason"] = "timeout"
        result["error"] = "Compatibility review exceeded its time limit."
    except subprocess.CalledProcessError as error:
        diagnostics["error_type"] = "CalledProcessError"
        diagnostics["exit_code"] = error.returncode
        if (
            isinstance(error.cmd, (list, tuple))
            and tuple(error.cmd[:2]) == ("git", "merge-tree")
            and error.returncode == 1
        ):
            diagnostics["reason"] = "merge_conflict"
        result["error"] = (
            f"Review tooling failed (exit {error.returncode}); no assessment is available."
        )
    except json.JSONDecodeError:
        diagnostics["error_type"] = "JSONDecodeError"
        result["error"] = "Codex did not return a valid JSON report."
    except ValueError as error:
        diagnostics.setdefault("error_type", "ValueError")
        result["error"] = str(error)
    except OSError as error:
        diagnostics["error_type"] = type(error).__name__
        result["error"] = (
            f"Review input, tool, or output unavailable ({type(error).__name__})."
        )
    diagnostics["elapsed_seconds"] = round(time.monotonic() - started, 1)
    write_report(output, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", help="Release tag, or source SHA in branch mode.")
    parser.add_argument(
        "--source-sha", default="", help="Expected qualification commit."
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--base-ref", default="", help="Target ref for a branch review."
    )
    parser.add_argument("--pr-number", default=0, type=int, help="Mirrored PR number.")
    args = parser.parse_args()
    result = run_review(
        args.candidate, args.source_sha, args.output_dir, args.base_ref, args.pr_number
    )
    verdict = result["review"]["verdict"] if result["review"] else "unavailable"
    print(
        "Compatibility review execution diagnostics: "
        + json.dumps(result["diagnostics"])
    )
    has_findings = bool(
        result["review"]
        and any(not f["previous_report_url"] for f in result["review"]["findings"])
    )
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a") as handle:
            handle.write(f"status={result['status']}\nverdict={verdict}\n")
            handle.write(f"has_findings={str(has_findings).lower()}\n")
    if result["status"] != "complete" or verdict != "no_unaddressed_breaks":
        print(
            f"::warning::Advisory compatibility review: {result['status']}, {verdict}. See report."
        )
    raise SystemExit(0 if result["status"] == "complete" else 1)


if __name__ == "__main__":
    main()
