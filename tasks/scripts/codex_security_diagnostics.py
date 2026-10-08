#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run a scan, retaining only allowlisted diagnostics suitable for public CI."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path


def read_document(path: Path) -> tuple[dict, str]:
    # Never echo parser errors, paths, or arbitrary scanner-generated text.
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return {}, "invalid"
        # Check the opened file too: the path may change after lstat().
        flags = (
            os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return {}, "invalid"
            data = stream.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            return {}, "oversized"
        document = json.loads(data)
        if isinstance(document, dict):
            return document, "available"
    except FileNotFoundError:
        return {}, "missing"
    except (OSError, ValueError, RecursionError):
        pass
    return {}, "invalid"


def coverage_summary(scan_dir: Path) -> dict:
    coverage, coverage_state = read_document(scan_dir / "coverage.json")
    manifest, manifest_state = read_document(scan_dir / "scan-manifest.json")
    scan = manifest.get("scan")
    status = scan.get("status") if isinstance(scan, dict) else None
    completeness = coverage.get("completeness")
    surfaces = coverage.get("surfaces")
    result = {
        "coverage_document": coverage_state,
        "manifest_document": manifest_state,
        "scan_status": status
        if status in ("completed", "failed", "canceled", "interrupted")
        else "unknown",
        "coverage": completeness
        if completeness in ("complete", "partial", "unknown")
        else "unknown",
        "surfaces_total": len(surfaces) if isinstance(surfaces, list) else None,
        "surfaces_needing_follow_up": sum(
            isinstance(surface, dict)
            and surface.get("disposition") == "needs_follow_up"
            for surface in surfaces
        )
        if isinstance(surfaces, list)
        else None,
    }
    for field, label in (
        ("deferred", "deferred_items"),
        ("explicitExclusions", "explicit_exclusions"),
        ("openQuestions", "open_questions"),
    ):
        value = coverage.get(field)
        result[label] = len(value) if isinstance(value, list) else None
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a scanner command is required")

    args.scan_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    before = shutil.disk_usage(args.scan_dir)
    minimum_free = before.free
    started = time.monotonic()
    next_progress = started + 60
    exit_code = 127
    # Raw output may contain findings or provider errors with sensitive text.
    # Discard it without consuming disk space or populating SCAN_DIR.
    try:
        with subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ) as process:
            while True:
                try:
                    exit_code = process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    minimum_free = min(
                        minimum_free, shutil.disk_usage(args.scan_dir).free
                    )
                    if time.monotonic() >= next_progress:
                        print(
                            f"Scan running: elapsed_seconds={round(time.monotonic() - started)} "
                            f"disk_free_bytes_min_sampled={minimum_free}",
                            flush=True,
                        )
                        next_progress = time.monotonic() + 60
            if exit_code < 0:
                exit_code = 128 - exit_code
    except OSError:
        print("::error::Could not execute the security scanner.")

    after = shutil.disk_usage(args.scan_dir)
    report = {
        "schema_version": 1,
        "exit_code": exit_code,
        "elapsed_seconds": round(time.monotonic() - started),
        "disk_total_bytes": before.total,
        "disk_free_bytes_before": before.free,
        "disk_free_bytes_min_sampled": min(minimum_free, after.free),
        "disk_free_bytes_after": after.free,
        "disk_sample_interval_seconds": 5,
        **coverage_summary(args.scan_dir),
    }
    rendered = json.dumps(report, indent=2) + "\n"
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if summary_path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary_path).open("a", encoding="utf-8") as summary:
            summary.write("### Codex Security execution diagnostics\n\n")
            summary.write(f"```json\n{rendered}```\n\n")
            summary.write(
                "Only fixed states and aggregate counts are published. "
                "Raw reports, findings, paths, reasons, and scanner logs are omitted. "
                "Disk minimum is sampled every 5 seconds, not a continuous measurement.\n"
            )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
