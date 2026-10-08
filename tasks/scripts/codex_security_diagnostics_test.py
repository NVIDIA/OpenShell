# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_security_diagnostics import coverage_summary

SCRIPT = Path(__file__).with_name("codex_security_diagnostics.py")
SENSITIVE = "PRIVATE_FINDING_secret_token_source_code"


@pytest.mark.parametrize("exit_code", [0, 2, 137])
def test_public_report_omits_sensitive_text_and_preserves_exit(tmp_path, exit_code):
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "coverage.json").write_text(
        json.dumps(
            {
                "completeness": "partial",
                "includePaths": [SENSITIVE],
                "surfaces": [
                    {"disposition": "needs_follow_up", "notes": SENSITIVE},
                    {"disposition": SENSITIVE, "label": SENSITIVE},
                ],
                "deferred": [{"reason": SENSITIVE, "paths": [SENSITIVE]}],
                "explicitExclusions": [{"reason": SENSITIVE}],
                "openQuestions": [{"question": SENSITIVE}],
                SENSITIVE: SENSITIVE,
            }
        )
    )
    (scan / "scan-manifest.json").write_text(
        json.dumps({"scan": {"status": "completed", "threatModel": SENSITIVE}})
    )
    (scan / "findings.json").write_text(SENSITIVE)
    output = tmp_path / "diagnostics.json"
    summary = tmp_path / "summary.md"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--scan-dir",
            str(scan),
            "--output",
            str(output),
            "--",
            sys.executable,
            "-c",
            f"import sys; print({SENSITIVE!r}); "
            f"print({SENSITIVE!r}, file=sys.stderr); sys.exit({exit_code})",
        ],
        env={**os.environ, "GITHUB_STEP_SUMMARY": str(summary)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == exit_code
    for public_output in (
        result.stdout,
        result.stderr,
        output.read_text(),
        summary.read_text(),
    ):
        assert SENSITIVE not in public_output
    report = json.loads(output.read_text())
    assert report["coverage"] == "partial"
    assert report["deferred_items"] == 1
    assert report["surfaces_needing_follow_up"] == 1
    assert report["disk_free_bytes_min_sampled"] <= report["disk_free_bytes_before"]


def test_scanner_output_does_not_exhaust_file_size_limit(tmp_path):
    pytest.importorskip("resource")
    output = tmp_path / "diagnostics.json"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--scan-dir",
            str(tmp_path / "scan"),
            "--output",
            str(output),
            "--",
            sys.executable,
            "-c",
            "import os, resource; "
            "resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024)); "
            "os.write(1, b'x' * 2048); os.write(1, b'x' * 2048); "
            "os.write(2, b'x' * 2048); os.write(2, b'x' * 2048)",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert json.loads(output.read_text())["exit_code"] == 0


@pytest.mark.parametrize("value", [SENSITIVE, {}, [], None, 7, True])
def test_unknown_enum_values_are_not_published(tmp_path, value):
    (tmp_path / "coverage.json").write_text(json.dumps({"completeness": value}))
    (tmp_path / "scan-manifest.json").write_text(
        json.dumps({"scan": {"status": value}})
    )
    report = coverage_summary(tmp_path)
    assert report["coverage"] == "unknown"
    assert report["scan_status"] == "unknown"
    assert SENSITIVE not in json.dumps(report)


def test_missing_invalid_and_symlinked_reports_do_not_echo_contents(tmp_path):
    assert coverage_summary(tmp_path)["coverage_document"] == "missing"
    path = tmp_path / "coverage.json"
    path.write_text(SENSITIVE)
    assert coverage_summary(tmp_path)["coverage_document"] == "invalid"
    path.unlink()
    path.symlink_to(tmp_path / "scan-manifest.json")
    assert coverage_summary(tmp_path)["coverage_document"] == "invalid"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires named pipes")
@pytest.mark.parametrize(
    ("filename", "field"),
    [
        ("coverage.json", "coverage_document"),
        ("scan-manifest.json", "manifest_document"),
    ],
)
def test_fifo_report_does_not_block_diagnostics(tmp_path, filename, field):
    scan = tmp_path / "scan"
    scan.mkdir()
    os.mkfifo(scan / filename)
    output = tmp_path / "diagnostics.json"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--scan-dir",
            str(scan),
            "--output",
            str(output),
            "--",
            sys.executable,
            "-c",
            "raise SystemExit(2)",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    assert result.returncode == 2
    report = json.loads(output.read_text())
    assert report["exit_code"] == 2
    assert report[field] == "invalid"


def test_scan_output_directory_stays_empty_until_scanner_writes(tmp_path):
    scan = tmp_path / "scan"
    output = tmp_path / "diagnostics.json"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--scan-dir",
            str(scan),
            "--output",
            str(output),
            "--",
            sys.executable,
            "-c",
            "import pathlib, sys; assert not list(pathlib.Path(sys.argv[1]).iterdir())",
            str(scan),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert json.loads(output.read_text())["coverage_document"] == "missing"
