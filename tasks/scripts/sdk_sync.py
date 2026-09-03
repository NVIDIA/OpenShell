#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""SDK proto sync utilities.

Drift detection is handled by per-SDK mise tasks (go:proto:drift,
sdk:ts:proto:drift) which output JSON DriftReport objects. This CLI
provides the workflow integration layer: issue management when drift
is detected and auto-closing when it resolves.

Subcommands:
  manage-issue   Create or update a GitHub drift issue (deduplicates by label)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _load_sdk_configs() -> dict[str, dict]:
    config_path = Path(__file__).resolve().parent.parent / "sdk-sync-config.json"
    config = json.loads(config_path.read_text())
    return {entry["name"]: entry for entry in config["include"]}


SDK_CONFIGS = _load_sdk_configs()

ISSUE_TEMPLATE = """\
## Proto Drift Report

**Summary**: {summary}

{file_table}
{build_section}
## Fix Commands

```bash
mise run {proto_task}    # Regenerate bindings
mise run {build_task}    # Verify build
mise run {test_task}     # Run tests
```

## Agent Instructions

This section is a ready-to-consume prompt for an AI agent. Copy it into your agent to produce a fix PR.

<details>
<summary>Agent prompt (click to expand)</summary>

{agent_section}
</details>
"""

BUILD_SECTION_TEMPLATE = """\
## Build Log

**Failed step**: `{failed_step}`

```
{log}
```

"""

AGENT_SECTION_TEMPLATE = """\
Fix proto drift in the {display_name} SDK.

## Context

The root `proto/` directory has changed and the {display_name} SDK's generated bindings are out of sync. The drifted files are: {drifted_names}.
{build_context}

## Steps

1. **Regenerate bindings**: Run `mise run {proto_task}` to regenerate language-specific bindings from the updated protos.
2. **Fix compilation errors**: Read the build log above. Update the SDK source code to handle new/changed/removed proto fields:
{source_dirs}
3. **Fix test failures**: Update tests that assert on proto types that changed shape.
4. **Verify**: Run `mise run {build_task}` and `mise run {test_task}` until both pass.
5. **Create a PR**: Commit all changes and create a PR referencing this issue.

## Scope

- Only modify files under `sdk/{sdk}/`. Do not change root `proto/` files.
- Do not change the proto definitions. Adapt the SDK to match them.
- Keep changes minimal: only fix what the proto changes broke.
"""


def _sdk_display_name(sdk: str) -> str:
    return SDK_CONFIGS[sdk]["display_name"]


def generate_issue_body(
    drift_report: dict,
    build_report: dict | None,
    sdk: str,
    max_log_lines: int = 500,
) -> str:
    paths = SDK_CONFIGS[sdk]
    files = drift_report.get("files", [])
    drifted_files = [f for f in files if f.get("status") != "synced"]
    return ISSUE_TEMPLATE.format(
        summary=drift_report.get("summary", "unknown"),
        file_table=_render_file_table(drifted_files),
        build_section=_render_build_section(build_report, max_log_lines),
        proto_task=paths["proto_task"],
        build_task=paths["build_task"],
        test_task=paths["test_task"],
        agent_section=_render_agent_section(sdk, drifted_files, build_report),
    )


# --- helpers ---


def _render_file_table(files: list[dict]) -> str:
    if not files:
        return ""
    lines = [
        "| File | Status | Diff Lines |",
        "|------|--------|------------|",
    ]
    for f in files:
        lines.append(f"| `{f['name']}` | {f['status']} | {f['diff_lines']} |")
    return "\n".join(lines) + "\n\n"


def _render_build_section(build_report: dict | None, max_log_lines: int) -> str:
    if not build_report or not build_report.get("failed_step"):
        return ""
    log_lines = build_report.get("log", "no log available").splitlines()
    log = "\n".join(log_lines[-max_log_lines:])
    return BUILD_SECTION_TEMPLATE.format(
        failed_step=build_report["failed_step"],
        log=log,
    )


def _render_agent_section(
    sdk: str, drifted_files: list[dict], build_report: dict | None
) -> str:
    paths = SDK_CONFIGS[sdk]
    display_name = _sdk_display_name(sdk)
    failed_step = build_report.get("failed_step") if build_report else None
    if drifted_files:
        drifted_names = ", ".join(f"`{f['name']}`" for f in drifted_files)
    elif sdk == "typescript":
        drifted_names = (
            "not individually tracked (run `mise run sdk:ts:proto && "
            "mise run sdk:ts:typecheck` to reproduce)"
        )
    else:
        drifted_names = "unknown"

    if failed_step:
        build_context = (
            f"\nThe SDK build fails at the `{failed_step}` step after regenerating protos. "
            "The build log above shows the exact error. Your job is to fix the "
            f"{display_name} SDK code so it compiles and passes tests with the updated protos."
        )
    else:
        build_context = "\nThe SDK build status is unknown. Check if it compiles after regeneration."

    source_dirs = "\n".join(f"   - `{path}`" for path in paths["source_dirs"])
    return AGENT_SECTION_TEMPLATE.format(
        display_name=display_name,
        drifted_names=drifted_names,
        build_context=build_context,
        proto_task=paths["proto_task"],
        source_dirs=source_dirs,
        build_task=paths["build_task"],
        test_task=paths["test_task"],
        sdk=sdk,
    )


def _run_cmd(
    cmd: list[str],
    cwd: str | None = None,
    capture: bool = False,
    stdin_data: str | None = None,
    timeout: int = 60,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=capture,
            text=True,
            input=stdin_data,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        command = " ".join(cmd)
        raise RuntimeError(
            f"Command timed out after {timeout} seconds: {command}"
        ) from None


def _ensure_label(repo: str, label: str, description: str) -> None:
    check = _run_cmd(["gh", "label", "view", label, "--repo", repo], capture=True)
    if check.returncode != 0:
        result = _run_cmd(
            [
                "gh",
                "label",
                "create",
                label,
                "--repo",
                repo,
                "--description",
                description,
                "--color",
                "D93F0B",
            ],
            capture=True,
        )
        if result.returncode != 0:
            details = result.stderr.strip() or "unknown error"
            raise RuntimeError(f"Failed to create label '{label}': {details}")


def _find_open_issue(repo: str, label: str) -> dict | None:
    result = _run_cmd(
        [
            "gh",
            "issue",
            "list",
            "--repo",
            repo,
            "--label",
            label,
            "--state",
            "open",
            "--json",
            "url,number",
            "--jq",
            ".[0]",
        ],
        capture=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        try:
            data = json.loads(result.stdout.strip())
            return {"url": data["url"], "number": str(data["number"])}
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return None


# --- public functions ---


def manage_issue(
    drift_report: dict,
    build_report: dict | None,
    sdk: str,
    repo: str,
    label: str,
) -> dict:
    try:
        return _manage_issue(drift_report, build_report, sdk, repo, label)
    except RuntimeError as error:
        return {
            "issue_url": "",
            "action": "error",
            "reason": str(error),
        }


def _manage_issue(
    drift_report: dict,
    build_report: dict | None,
    sdk: str,
    repo: str,
    label: str,
) -> dict:
    try:
        _ensure_label(repo, label, f"Proto drift detected for {sdk} SDK")
    except RuntimeError as error:
        return {
            "issue_url": "",
            "action": "error",
            "reason": str(error),
        }

    body = generate_issue_body(drift_report, build_report, sdk)
    title = f"SDK proto drift: {sdk}"

    existing = _find_open_issue(repo, label)
    if existing:
        result = _run_cmd(
            [
                "gh",
                "issue",
                "edit",
                existing["number"],
                "--repo",
                repo,
                "--body-file",
                "-",
            ],
            capture=True,
            stdin_data=body,
        )
        if result.returncode == 0:
            return {"issue_url": existing["url"], "action": "updated"}
        return {
            "issue_url": "",
            "action": "error",
            "reason": "Failed to update issue",
        }

    result = _run_cmd(
        [
            "gh",
            "issue",
            "create",
            "--repo",
            repo,
            "--title",
            title,
            "--body-file",
            "-",
            "--label",
            label,
        ],
        capture=True,
        stdin_data=body,
    )
    if result.returncode == 0:
        url = result.stdout.strip()
        return {"issue_url": url, "action": "created"}
    return {
        "issue_url": "",
        "action": "error",
        "reason": "Failed to create issue",
    }


# --- CLI ---


def _load_json_arg(value: str) -> dict | list:
    if value == "-":
        return json.load(sys.stdin)
    return json.loads(value)


def cmd_manage_issue(args: argparse.Namespace) -> int:
    drift_report = _load_json_arg(args.drift_report)
    build_report = None
    if args.build_report:
        build_report = _load_json_arg(args.build_report)
    result = manage_issue(drift_report, build_report, args.sdk, args.repo, args.label)
    print(json.dumps(result))
    return 1 if result.get("action") == "error" else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SDK proto sync utilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    mi = sub.add_parser("manage-issue", help="Create or update a drift issue")
    mi.add_argument("--drift-report", required=True, help="Drift report JSON")
    mi.add_argument("--build-report", help="Build report JSON")
    mi.add_argument(
        "--sdk",
        required=True,
        choices=list(SDK_CONFIGS.keys()),
        help="SDK name",
    )
    mi.add_argument("--repo", required=True, help="GitHub repo (owner/name)")
    mi.add_argument("--label", required=True, help="Issue label for deduplication")

    args = parser.parse_args()
    handlers = {
        "manage-issue": cmd_manage_issue,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
