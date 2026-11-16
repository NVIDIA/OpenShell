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
import threading
import time
from pathlib import Path

PRIVATE_LOG_LIMIT = 4 * 1024 * 1024


def write_private_log(source, destination) -> None:
    remaining = PRIVATE_LOG_LIMIT
    while chunk := source.read(64 * 1024):
        destination.write(chunk[:remaining])
        remaining = max(0, remaining - len(chunk))


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
    parser.add_argument("--private-log", type=Path)
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
    # The caller must encrypt private output before retention. Keep it outside
    # SCAN_DIR, which the scanner expects to be empty.
    private_log = (
        os.fdopen(
            os.open(args.private_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        )
        if args.private_log
        else None
    )
    try:
        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE if private_log else subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        ) as process:
            if private_log:
                reader = threading.Thread(
                    target=write_private_log, args=(process.stdout, private_log)
                )
                reader.start()
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
            if private_log:
                reader.join()
    except OSError:
        print("::error::Could not execute the security scanner.")
    finally:
        if private_log:
            private_log.close()

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
