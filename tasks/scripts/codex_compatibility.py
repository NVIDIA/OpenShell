# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run an advisory, cumulative release compatibility review with Codex."""

import argparse
import asyncio
import json
import os
import re
import subprocess
import tempfile
from importlib.metadata import version
from pathlib import Path

# Installed only in the review workflow's isolated Python environment.
import openai_codex  # ty: ignore[unresolved-import]
from check_proto_compatibility import git, train_policy
from codex_compatibility_report import validate_review, write_report

ASSETS = Path(__file__).resolve().parents[2] / ".github" / "prompts"
MODEL = "openai/openai/gpt-5.6-sol"
ENDPOINT = "https://inference-api.nvidia.com/v1"


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
        "baseline_tag": baseline,
        "baseline_sha": git(
            "rev-parse", "--verify", f"refs/tags/{baseline}^{{commit}}"
        ),
        "train": train,
        "allows_breaks": allows_breaks,
    }


async def invoke_codex(context: dict, directory: Path) -> dict:
    # Git objects expose both revisions without loading candidate-side agent
    # instructions, configuration, skills, or hooks into the review workspace.
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
        'model_providers.nvidia.name="NVIDIA Inference"',
        f'model_providers.nvidia.base_url="{ENDPOINT}"',
        'model_providers.nvidia.env_key="NVIDIA_INFERENCE_API_KEY"',
        'model_providers.nvidia.wire_api="responses"',
        "model_providers.nvidia.supports_websockets=false",
        'model_reasoning_effort="medium"',
        'web_search="disabled"',
        "project_doc_max_bytes=0",
        "features.hooks=false",
        "features.plugins=false",
        "features.multi_agent=false",
        "features.multi_agent_v2=false",
        'shell_environment_policy.inherit="none"',
        "shell_environment_policy.ignore_default_excludes=false",
    )
    prompt = (ASSETS / "compatibility-review.md").read_text()
    prompt += "\nReview context:\n" + json.dumps(context)
    schema = json.loads((ASSETS / "compatibility-review.schema.json").read_text())
    codex = openai_codex.AsyncCodex(
        openai_codex.CodexConfig(cwd=str(directory), config_overrides=settings)
    )
    # Raw agent output can include inspected source or tool output. Publish only
    # the validated final report, never the transcript or credential environment.
    try:
        async with asyncio.timeout(1800):
            thread = await codex.thread_start(
                cwd=str(directory),
                model=MODEL,
                model_provider="nvidia",
                sandbox=openai_codex.Sandbox.read_only,
                approval_mode=openai_codex.ApprovalMode.deny_all,
                ephemeral=True,
            )
            result = await thread.run(prompt, output_schema=schema)
    except (openai_codex.CodexError, RuntimeError, ValueError) as error:
        raise ValueError(
            f"Codex SDK review failed ({type(error).__name__}); no assessment is available."
        ) from None
    finally:
        await codex.close()
    if result.status.value != "completed" or not result.final_response:
        raise ValueError("Codex did not complete the compatibility review.")
    review = json.loads(result.final_response)
    validate_review(review)
    return review


def run_review(tag: str, expected_sha: str, output: Path) -> dict:
    result = {
        "schema_version": 1,
        "advisory": True,
        "status": "error",
        "context": {},
        "review": None,
        "error": "",
        "model": MODEL,
        "reasoning_effort": "medium",
        "codex_version": "",
        "codex_sdk_version": "",
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    try:
        result["context"] = resolve_candidate(tag, expected_sha)
        if not os.environ.get("NVIDIA_INFERENCE_API_KEY"):
            raise ValueError("NVIDIA inference credential is missing.")
        result["codex_version"] = version("openai-codex-cli-bin")
        result["codex_sdk_version"] = version("openai-codex")
        with tempfile.TemporaryDirectory(
            prefix="openshell-compatibility-"
        ) as temporary:
            result["review"] = asyncio.run(
                invoke_codex(result["context"], Path(temporary))
            )
        result["status"] = (
            "incomplete" if result["review"]["unreviewed_surfaces"] else "complete"
        )
    except TimeoutError:
        result["error"] = "Compatibility review exceeded its time limit."
    except subprocess.CalledProcessError as error:
        result["error"] = (
            f"Review tooling failed (exit {error.returncode}); no assessment is available."
        )
    except json.JSONDecodeError:
        result["error"] = "Codex did not return a valid JSON report."
    except ValueError as error:
        result["error"] = str(error)
    except OSError as error:
        result["error"] = (
            f"Review input, tool, or output unavailable ({type(error).__name__})."
        )
    write_report(output, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", help="Candidate or stable release tag.")
    parser.add_argument(
        "--source-sha", default="", help="Expected qualification commit."
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    result = run_review(args.candidate, args.source_sha, args.output_dir)
    verdict = result["review"]["verdict"] if result["review"] else "unavailable"
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a") as handle:
            handle.write(f"status={result['status']}\nverdict={verdict}\n")
    if result["status"] != "complete" or verdict != "no_unaddressed_breaks":
        print(
            f"::warning::Advisory compatibility review: {result['status']}, {verdict}. See report."
        )
    raise SystemExit(0 if result["status"] == "complete" else 1)


if __name__ == "__main__":
    main()
