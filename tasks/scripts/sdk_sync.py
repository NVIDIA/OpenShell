#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""SDK proto sync utilities.

Subcommands:
  drift-report   Compare proto files between upstream and SDK copies
  dashboard      Generate wiki dashboard markdown from drift/build reports
  issue-body     Generate GitHub issue body for a drifted SDK
  wiki-push      Clone wiki repo, update a page, commit, push
  manage-issue   Create or update a GitHub drift issue (deduplicates by label)
  dispatch       Fire a repository_dispatch event for agent pickup
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class FileDrift:
    name: str
    status: str  # synced, modified, added, removed
    diff_lines: int


@dataclass(frozen=True)
class DriftReport:
    sdk: str
    synced: bool
    files: list[FileDrift]
    summary: str


def compute_drift(
    sdk: str, upstream_path: Path, sdk_path: Path, proto_files: list[str]
) -> DriftReport:
    drifted = 0
    files: list[FileDrift] = []

    for name in proto_files:
        upstream = upstream_path / name
        local = sdk_path / name

        if not upstream.exists() and not local.exists():
            continue

        if not upstream.exists() and local.exists():
            files.append(FileDrift(name, "removed", _line_count(local)))
            drifted += 1
        elif upstream.exists() and not local.exists():
            files.append(FileDrift(name, "added", _line_count(upstream)))
            drifted += 1
        else:
            upstream_lines = upstream.read_text().splitlines(keepends=True)
            local_lines = local.read_text().splitlines(keepends=True)
            diff = list(
                difflib.unified_diff(local_lines, upstream_lines, n=0)
            )
            if diff:
                files.append(FileDrift(name, "modified", len(diff)))
                drifted += 1
            else:
                files.append(FileDrift(name, "synced", 0))

    synced = drifted == 0
    summary = "all files synced" if synced else f"{drifted} file(s) drifted"
    return DriftReport(sdk=sdk, synced=synced, files=files, summary=summary)


def generate_dashboard(
    drift_reports: list[dict],
    build_reports: list[dict],
) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# SDK Sync Status",
        "",
        f"*Last updated: {timestamp}*",
        "",
        "## Overview",
        "",
        "| SDK | Proto Synced | Build | Issue |",
        "|-----|-------------|-------|-------|",
    ]

    drift_details: list[str] = []

    for drift in drift_reports:
        sdk = drift.get("sdk", "unknown")
        synced = drift.get("synced", True)
        build = _find_build(build_reports, sdk)

        if synced:
            proto_status = "synced"
            build_status = "n/a"
            issue_link = ""
        else:
            proto_status = "**drifted**"
            if build and not build.get("success", True):
                build_status = "**failing**"
            else:
                build_status = "passing"
            issue_link = drift.get("issue_url", "")
            if issue_link:
                issue_num = issue_link.rstrip("/").split("/")[-1]
                issue_link = f"[#{issue_num}]({issue_link})"

        lines.append(f"| {sdk.capitalize()} | {proto_status} | {build_status} | {issue_link} |")

        if not synced:
            drift_details.extend(_format_drift_details(drift))

    if drift_details:
        lines.append("")
        lines.append("## Drift Details")
        lines.append("")
        lines.extend(drift_details)

    lines.append("")
    return "\n".join(lines)


def generate_issue_body(
    drift_report: dict,
    build_report: dict | None,
    sdk: str,
    max_log_lines: int = 500,
) -> str:
    sections: list[str] = []

    # Proto drift section
    sections.append("## Proto Drift Report")
    sections.append("")
    summary = drift_report.get("summary", "unknown")
    sections.append(f"**Summary**: {summary}")
    sections.append("")

    files = drift_report.get("files", [])
    if files:
        sections.append("| File | Status | Diff Lines |")
        sections.append("|------|--------|------------|")
        for f in files:
            if f.get("status") != "synced":
                sections.append(
                    f"| `{f['name']}` | {f['status']} | {f['diff_lines']} |"
                )
    sections.append("")

    # Build log section
    if build_report:
        sections.append("## Build Log")
        sections.append("")
        failed_step = build_report.get("failed_step", "unknown")
        sections.append(f"**Failed step**: `{failed_step}`")
        sections.append("")
        log = build_report.get("log", "no log available")
        log_lines = log.splitlines()
        if len(log_lines) > max_log_lines:
            log = "\n".join(log_lines[-max_log_lines:])
        sections.append("```")
        sections.append(log)
        sections.append("```")
        sections.append("")

    # Affected files section
    sections.append("## Affected Files")
    sections.append("")
    for f in files:
        if f.get("status") != "synced":
            sections.append(f"- `sdk/{sdk}/proto/{f['name']}`")
    sections.append("")

    # Fix commands section
    sections.append("## Fix Commands")
    sections.append("")
    sections.append("```bash")
    sections.append(f"mise run {sdk}:proto:sync    # Copy protos from root")
    sections.append(f"mise run {sdk}:proto:gen     # Regenerate bindings")
    sections.append(f"mise run {sdk}:build         # Verify build")
    sections.append(f"mise run {sdk}:test          # Run tests")
    sections.append("```")
    sections.append("")

    # Agent instructions section
    drifted_files = [f for f in files if f.get("status") != "synced"]
    drifted_names = ", ".join(f"`{f['name']}`" for f in drifted_files) or "unknown"
    failed_step = ""
    if build_report:
        failed_step = build_report.get("failed_step", "")

    sections.append("## Agent Instructions")
    sections.append("")
    sections.append(
        "This section is a ready-to-consume prompt for an AI agent. "
        "Copy it into your agent to produce a fix PR."
    )
    sections.append("")
    sections.append("<details>")
    sections.append("<summary>Agent prompt (click to expand)</summary>")
    sections.append("")

    prompt_lines = [
        f"Fix proto drift in the {sdk.capitalize()} SDK.",
        "",
        "## Context",
        "",
        f"The root `proto/` directory has changed and the {sdk.capitalize()} SDK's local",
        f"copies in `sdk/{sdk}/proto/` are out of sync. The drifted files are: {drifted_names}.",
    ]

    if failed_step:
        prompt_lines.append(
            f"The SDK build fails at the `{failed_step}` step after syncing protos."
        )
        prompt_lines.append(
            "The build log above shows the exact error. Your job is to fix the"
        )
        prompt_lines.append(
            f"{sdk.capitalize()} SDK code so it compiles and passes tests with the updated protos."
        )
    else:
        prompt_lines.append("The SDK build status is unknown. Check if it compiles after syncing.")

    prompt_lines.extend([
        "",
        "## Steps",
        "",
        "1. **Sync protos**: Run `mise run {sdk}:proto:sync` to copy the latest proto files from `proto/` to `sdk/{sdk}/proto/`.",
        "2. **Regenerate bindings**: Run `mise run {sdk}:proto:gen` to regenerate language-specific bindings from the updated protos.",
        "3. **Fix compilation errors**: Read the build log above. Update the SDK source code to handle new/changed/removed proto fields:",
        f"   - Converter layer: `sdk/{sdk}/openshell/v1/internal/converter/`",
        f"   - Public types: `sdk/{sdk}/openshell/v1/types/`",
        f"   - Client methods: `sdk/{sdk}/openshell/v1/`",
        "4. **Fix test failures**: Update tests that assert on proto types that changed shape.",
        "5. **Verify**: Run `mise run {sdk}:build` and `mise run {sdk}:test` until both pass.",
        "6. **Create a PR**: Commit all changes and create a PR referencing this issue.",
        "",
        "## Scope",
        "",
        f"- Only modify files under `sdk/{sdk}/`. Do not change root `proto/` files.",
        "- Do not change the proto definitions. Adapt the SDK to match them.",
        "- Keep changes minimal: only fix what the proto changes broke.",
        "",
        "## SDK Documentation",
        "",
        f"- SDK source: `sdk/{sdk}/`",
        f"- Mise tasks: `mise tasks --hidden | grep {sdk}:`",
        f"- Proto files tracked: `openshell.proto`, `datamodel.proto`, `sandbox.proto`",
        f"- Converter pattern: each proto message maps to a domain type in `sdk/{sdk}/openshell/v1/types/` via a converter in `sdk/{sdk}/openshell/v1/internal/converter/`",
    ])

    # Format the prompt lines with the sdk variable resolved
    for line in prompt_lines:
        sections.append(line.format(sdk=sdk))

    sections.append("")
    sections.append("</details>")
    sections.append("")

    return "\n".join(sections)


# --- helpers ---


def _line_count(path: Path) -> int:
    return len(path.read_text().splitlines())


def _find_build(build_reports: list[dict], sdk: str) -> dict | None:
    for b in build_reports:
        if b.get("sdk") == sdk:
            return b
    return None


def _format_drift_details(drift: dict) -> list[str]:
    sdk = drift.get("sdk", "unknown")
    lines = [
        f"### {sdk.capitalize()} SDK",
        "",
        f"**Status**: {drift.get('summary', 'unknown')}",
        "",
        "| File | Status | Diff Lines |",
        "|------|--------|------------|",
    ]
    for f in drift.get("files", []):
        lines.append(f"| {f['name']} | {f['status']} | {f['diff_lines']} |")
    lines.append("")
    return lines


# --- CLI ---

DEFAULT_PROTO_FILES = ["openshell.proto", "datamodel.proto", "sandbox.proto"]


def cmd_drift_report(args: argparse.Namespace) -> int:
    upstream = Path(args.upstream_path)
    sdk_path = Path(args.sdk_path)

    if not upstream.is_dir():
        print(f"ERROR: Upstream proto directory not found: {upstream}", file=sys.stderr)
        return 1

    proto_files = args.proto_files or DEFAULT_PROTO_FILES
    report = compute_drift(args.sdk, upstream, sdk_path, proto_files)
    print(json.dumps(asdict(report), separators=(",", ":")))
    return 0 if report.synced else 1


def cmd_dashboard(args: argparse.Namespace) -> int:
    drift_reports = _load_json_arg(args.drift_report)
    if not isinstance(drift_reports, list):
        drift_reports = [drift_reports]

    build_reports = []
    if args.build_report:
        br = _load_json_arg(args.build_report)
        build_reports = br if isinstance(br, list) else [br]

    md = generate_dashboard(drift_reports, build_reports)

    if args.output:
        Path(args.output).write_text(md)
        print(f"Dashboard written to {args.output}")
    else:
        print(md)
    return 0


def cmd_issue_body(args: argparse.Namespace) -> int:
    drift_report = _load_json_arg(args.drift_report)
    build_report = None
    if args.build_report:
        build_report = _load_json_arg(args.build_report)

    md = generate_issue_body(
        drift_report, build_report, args.sdk, max_log_lines=args.max_log_lines
    )
    print(md)
    return 0


def wiki_push(content_path: Path, page_name: str, repo: str) -> dict:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        return {"success": False, "reason": "GITHUB_TOKEN not set"}

    work_dir = tempfile.mkdtemp()
    try:
        clone_url = f"https://x-access-token:{token}@github.com/{repo}.wiki.git"
        result = _run_cmd(["git", "clone", clone_url, work_dir], capture=True)
        if result.returncode != 0:
            return {"success": False, "reason": "Failed to clone wiki repository"}

        shutil.copy2(str(content_path), os.path.join(work_dir, f"{page_name}.md"))

        _run_cmd(["git", "config", "user.name", "github-actions[bot]"], cwd=work_dir)
        _run_cmd(["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"], cwd=work_dir)
        _run_cmd(["git", "add", f"{page_name}.md"], cwd=work_dir)

        diff = _run_cmd(["git", "diff", "--cached", "--quiet"], cwd=work_dir, capture=True)
        if diff.returncode == 0:
            return {"success": True, "reason": "No changes to dashboard"}

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        _run_cmd(["git", "commit", "-m", f"Update {page_name} ({timestamp})"], cwd=work_dir)

        push = _run_cmd(["git", "push"], cwd=work_dir, capture=True)
        if push.returncode != 0:
            return {"success": False, "reason": "Failed to push wiki update"}

        return {"success": True, "reason": "Wiki updated"}
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def manage_issue(
    drift_report: dict,
    build_report: dict | None,
    sdk: str,
    repo: str,
    label: str,
) -> dict:
    _ensure_label(repo, label, f"Proto drift detected for {sdk} SDK")

    body = generate_issue_body(drift_report, build_report, sdk)
    title = f"SDK proto drift: {sdk}"

    existing = _find_open_issue(repo, label)
    if existing:
        result = _run_cmd(
            ["gh", "issue", "edit", existing["number"], "--repo", repo, "--body", body],
            capture=True,
        )
        if result.returncode == 0:
            return {"issue_url": existing["url"], "action": "updated"}
        return {"issue_url": "", "action": "skipped", "reason": "Failed to update issue"}

    result = _run_cmd(
        ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body, "--label", label],
        capture=True,
    )
    if result.returncode == 0:
        url = result.stdout.strip()
        return {"issue_url": url, "action": "created"}
    return {"issue_url": "", "action": "skipped", "reason": "Failed to create issue"}


def fire_dispatch(repo: str, issue_url: str, sdk: str, drift_summary: str) -> dict:
    payload = json.dumps({"issue_url": issue_url, "sdk": sdk, "drift_summary": drift_summary})
    result = _run_cmd(
        ["gh", "api", f"repos/{repo}/dispatches", "--method", "POST",
         "-f", "event_type=sdk-sync-drift", "--argjson", "client_payload", payload],
        capture=True,
    )
    if result.returncode == 0:
        return {"success": True}
    return {"success": False, "reason": result.stderr.strip() or "dispatch failed"}


def _run_cmd(
    cmd: list[str], cwd: str | None = None, capture: bool = False
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, capture_output=capture, text=True,
    )


def _ensure_label(repo: str, label: str, description: str) -> None:
    check = _run_cmd(["gh", "label", "view", label, "--repo", repo], capture=True)
    if check.returncode != 0:
        _run_cmd(
            ["gh", "label", "create", label, "--repo", repo,
             "--description", description, "--color", "D93F0B"],
            capture=True,
        )


def _find_open_issue(repo: str, label: str) -> dict | None:
    result = _run_cmd(
        ["gh", "issue", "list", "--repo", repo, "--label", label,
         "--state", "open", "--json", "url,number", "--jq", ".[0]"],
        capture=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        try:
            data = json.loads(result.stdout.strip())
            return {"url": data["url"], "number": str(data["number"])}
        except (json.JSONDecodeError, KeyError):
            pass
    return None


def cmd_wiki_push(args: argparse.Namespace) -> int:
    content = Path(args.content)
    if not content.exists():
        print(f"ERROR: Content file not found: {content}", file=sys.stderr)
        return 1
    result = wiki_push(content, args.page_name, args.repo)
    print(json.dumps(result))
    return 0 if result["success"] else 0  # always exit 0 (graceful degradation)


def cmd_manage_issue(args: argparse.Namespace) -> int:
    drift_report = _load_json_arg(args.drift_report)
    build_report = None
    if args.build_report:
        build_report = _load_json_arg(args.build_report)
    result = manage_issue(drift_report, build_report, args.sdk, args.repo, args.label)
    print(json.dumps(result))
    return 0


def cmd_dispatch(args: argparse.Namespace) -> int:
    result = fire_dispatch(args.repo, args.issue_url, args.sdk, args.drift_summary)
    print(json.dumps(result))
    return 0


def _load_json_arg(value: str) -> dict | list:
    if value == "-":
        return json.load(sys.stdin)
    p = Path(value)
    if p.exists():
        return json.loads(p.read_text())
    return json.loads(value)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SDK proto sync utilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # drift-report
    dr = sub.add_parser("drift-report", help="Compare proto files for drift")
    dr.add_argument("--sdk", required=True, help="SDK name (e.g. go)")
    dr.add_argument("--upstream-path", required=True, help="Path to upstream proto/")
    dr.add_argument("--sdk-path", required=True, help="Path to SDK proto copy")
    dr.add_argument(
        "--proto-files", nargs="*", help="Proto files to check (default: 3 core files)"
    )

    # dashboard
    db = sub.add_parser("dashboard", help="Generate wiki dashboard markdown")
    db.add_argument(
        "--drift-report", required=True, help="Drift report JSON (file, string, or -)"
    )
    db.add_argument("--build-report", help="Build report JSON (file, string, or -)")
    db.add_argument("--output", help="Output file path (stdout if omitted)")

    # issue-body
    ib = sub.add_parser("issue-body", help="Generate issue body markdown")
    ib.add_argument(
        "--drift-report", required=True, help="Drift report JSON (file, string, or -)"
    )
    ib.add_argument("--build-report", help="Build report JSON (file, string, or -)")
    ib.add_argument("--sdk", required=True, help="SDK name (e.g. go)")
    ib.add_argument(
        "--max-log-lines", type=int, default=500, help="Max build log lines (default: 500)"
    )

    # wiki-push
    wp = sub.add_parser("wiki-push", help="Push a page to the GitHub wiki")
    wp.add_argument("--content", required=True, help="Path to markdown file to push")
    wp.add_argument("--page-name", required=True, help="Wiki page name (without .md)")
    wp.add_argument("--repo", required=True, help="GitHub repo (owner/name)")

    # manage-issue
    mi = sub.add_parser("manage-issue", help="Create or update a drift issue")
    mi.add_argument("--drift-report", required=True, help="Drift report JSON")
    mi.add_argument("--build-report", help="Build report JSON")
    mi.add_argument("--sdk", required=True, help="SDK name")
    mi.add_argument("--repo", required=True, help="GitHub repo (owner/name)")
    mi.add_argument("--label", required=True, help="Issue label for deduplication")

    # dispatch
    dp = sub.add_parser("dispatch", help="Fire repository_dispatch event")
    dp.add_argument("--repo", required=True, help="GitHub repo (owner/name)")
    dp.add_argument("--issue-url", required=True, help="Issue URL")
    dp.add_argument("--sdk", required=True, help="SDK name")
    dp.add_argument("--drift-summary", required=True, help="Drift summary text")

    args = parser.parse_args()
    handlers = {
        "drift-report": cmd_drift_report,
        "dashboard": cmd_dashboard,
        "issue-body": cmd_issue_body,
        "wiki-push": cmd_wiki_push,
        "manage-issue": cmd_manage_issue,
        "dispatch": cmd_dispatch,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
