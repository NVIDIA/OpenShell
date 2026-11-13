# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for tasks/scripts/sdk_sync.py.

Run via: uv run --no-project --with pytest pytest tasks/scripts/sdk_sync_test.py
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from sdk_sync import (
    DriftReport,
    FileDrift,
    compute_drift,
    fire_dispatch,
    generate_dashboard,
    generate_issue_body,
    manage_issue,
    wiki_push,
)


@pytest.fixture
def proto_dirs(tmp_path: Path):
    upstream = tmp_path / "proto"
    upstream.mkdir()
    sdk = tmp_path / "sdk_proto"
    sdk.mkdir()
    return upstream, sdk


PROTO_FILES = ["openshell.proto", "datamodel.proto", "sandbox.proto"]


class TestComputeDrift:
    def test_all_synced(self, proto_dirs):
        upstream, sdk = proto_dirs
        for name in PROTO_FILES:
            content = f"syntax = 'proto3';\npackage {name};\n"
            (upstream / name).write_text(content)
            (sdk / name).write_text(content)

        report = compute_drift("go", upstream, sdk, PROTO_FILES)
        assert report.synced is True
        assert report.summary == "all files synced"
        assert all(f.status == "synced" for f in report.files)

    def test_modified_file(self, proto_dirs):
        upstream, sdk = proto_dirs
        for name in PROTO_FILES:
            (upstream / name).write_text(f"syntax = 'proto3';\npackage {name};\n")
            (sdk / name).write_text(f"syntax = 'proto3';\npackage {name};\n")

        (upstream / "openshell.proto").write_text(
            "syntax = 'proto3';\npackage openshell;\nmessage NewField {}\n"
        )

        report = compute_drift("go", upstream, sdk, PROTO_FILES)
        assert report.synced is False
        assert "1 file(s) drifted" in report.summary

        modified = [f for f in report.files if f.status == "modified"]
        assert len(modified) == 1
        assert modified[0].name == "openshell.proto"
        assert modified[0].diff_lines > 0

    def test_added_file(self, proto_dirs):
        upstream, sdk = proto_dirs
        (upstream / "openshell.proto").write_text("syntax = 'proto3';\n")

        report = compute_drift("go", upstream, sdk, ["openshell.proto"])
        assert report.synced is False
        added = [f for f in report.files if f.status == "added"]
        assert len(added) == 1
        assert added[0].name == "openshell.proto"

    def test_removed_file(self, proto_dirs):
        upstream, sdk = proto_dirs
        (sdk / "openshell.proto").write_text("syntax = 'proto3';\n")

        report = compute_drift("go", upstream, sdk, ["openshell.proto"])
        assert report.synced is False
        removed = [f for f in report.files if f.status == "removed"]
        assert len(removed) == 1

    def test_missing_both(self, proto_dirs):
        upstream, sdk = proto_dirs
        report = compute_drift("go", upstream, sdk, ["nonexistent.proto"])
        assert report.synced is True
        assert len(report.files) == 0


class TestGenerateDashboard:
    def test_all_synced(self):
        drift = [{"sdk": "go", "synced": True, "files": [], "summary": "all files synced"}]
        md = generate_dashboard(drift, [])
        assert "synced" in md
        assert "n/a" in md
        assert "Drift Details" not in md

    def test_drifted_with_build_failure(self):
        drift = [
            {
                "sdk": "go",
                "synced": False,
                "files": [{"name": "openshell.proto", "status": "modified", "diff_lines": 5}],
                "summary": "1 file(s) drifted",
            }
        ]
        build = [{"sdk": "go", "success": False, "failed_step": "build", "log": "error"}]
        md = generate_dashboard(drift, build)
        assert "**drifted**" in md
        assert "**failing**" in md
        assert "Drift Details" in md

    def test_issue_link_formatting(self):
        drift = [
            {
                "sdk": "go",
                "synced": False,
                "files": [],
                "summary": "drifted",
                "issue_url": "https://github.com/NVIDIA/OpenShell/issues/123",
            }
        ]
        md = generate_dashboard(drift, [])
        assert "[#123]" in md


class TestGenerateIssueBody:
    def test_basic_issue_body(self):
        drift = {
            "sdk": "go",
            "synced": False,
            "files": [{"name": "openshell.proto", "status": "modified", "diff_lines": 5}],
            "summary": "1 file(s) drifted",
        }
        md = generate_issue_body(drift, None, "go")
        assert "## Proto Drift Report" in md
        assert "`openshell.proto`" in md
        assert "## Fix Commands" in md
        assert "mise run go:proto:sync" in md

    def test_with_build_log(self):
        drift = {"sdk": "go", "synced": False, "files": [], "summary": "drifted"}
        build = {"sdk": "go", "success": False, "failed_step": "build", "log": "error here"}
        md = generate_issue_body(drift, build, "go")
        assert "## Build Log" in md
        assert "`build`" in md
        assert "error here" in md

    def test_log_truncation(self):
        long_log = "\n".join(f"line {i}" for i in range(1000))
        drift = {"sdk": "go", "synced": False, "files": [], "summary": "drifted"}
        build = {"sdk": "go", "success": False, "failed_step": "test", "log": long_log}
        md = generate_issue_body(drift, build, "go", max_log_lines=500)
        log_section = md.split("```")[1]
        assert log_section.strip().count("\n") <= 500
        assert "line 999" in md
        assert "line 0" not in md

    def test_affected_files_section(self):
        drift = {
            "sdk": "go",
            "synced": False,
            "files": [
                {"name": "a.proto", "status": "modified", "diff_lines": 3},
                {"name": "b.proto", "status": "synced", "diff_lines": 0},
            ],
            "summary": "1 file(s) drifted",
        }
        md = generate_issue_body(drift, None, "go")
        assert "`sdk/go/proto/a.proto`" in md
        assert "b.proto" not in md.split("## Affected Files")[1].split("## Fix")[0]

    def test_agent_instructions_present(self):
        drift = {
            "sdk": "go",
            "synced": False,
            "files": [{"name": "openshell.proto", "status": "modified", "diff_lines": 5}],
            "summary": "1 file(s) drifted",
        }
        build = {"sdk": "go", "success": False, "failed_step": "build", "log": "error"}
        md = generate_issue_body(drift, build, "go")
        assert "## Agent Instructions" in md
        assert "Agent prompt" in md
        assert "mise run go:proto:sync" in md
        assert "sdk/go/openshell/v1/internal/converter/" in md
        assert "sdk/go/openshell/v1/types/" in md
        assert "Create a PR" in md

    def test_agent_instructions_references_drifted_files(self):
        drift = {
            "sdk": "go",
            "synced": False,
            "files": [
                {"name": "openshell.proto", "status": "modified", "diff_lines": 10},
                {"name": "sandbox.proto", "status": "added", "diff_lines": 3},
            ],
            "summary": "2 file(s) drifted",
        }
        md = generate_issue_body(drift, None, "go")
        agent_section = md.split("## Agent Instructions")[1]
        assert "`openshell.proto`" in agent_section
        assert "`sandbox.proto`" in agent_section

    def test_agent_instructions_includes_failed_step(self):
        drift = {"sdk": "go", "synced": False, "files": [], "summary": "drifted"}
        build = {"sdk": "go", "success": False, "failed_step": "test", "log": "fail"}
        md = generate_issue_body(drift, build, "go")
        agent_section = md.split("## Agent Instructions")[1]
        assert "`test`" in agent_section
        assert "fails at" in agent_section.lower()


def _mock_run(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


class TestWikiPush:
    @patch("sdk_sync._run_cmd")
    @patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"})
    def test_successful_push(self, mock_run, tmp_path):
        content = tmp_path / "dashboard.md"
        content.write_text("# Dashboard")

        mock_run.side_effect = [
            _mock_run(0),  # git clone
            _mock_run(0),  # git config user.name
            _mock_run(0),  # git config user.email
            _mock_run(0),  # git add
            _mock_run(1),  # git diff --cached --quiet (has changes)
            _mock_run(0),  # git commit
            _mock_run(0),  # git push
        ]

        result = wiki_push(content, "SDK-Sync-Status", "NVIDIA/OpenShell")
        assert result["success"] is True

    @patch("sdk_sync._run_cmd")
    @patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"})
    def test_clone_failure(self, mock_run, tmp_path):
        content = tmp_path / "dashboard.md"
        content.write_text("# Dashboard")
        mock_run.return_value = _mock_run(128)

        result = wiki_push(content, "SDK-Sync-Status", "NVIDIA/OpenShell")
        assert result["success"] is False
        assert "clone" in result["reason"].lower()

    @patch.dict("os.environ", {}, clear=True)
    def test_missing_token(self, tmp_path):
        content = tmp_path / "dashboard.md"
        content.write_text("# Dashboard")
        os.environ.pop("GITHUB_TOKEN", None)
        result = wiki_push(content, "SDK-Sync-Status", "NVIDIA/OpenShell")
        assert result["success"] is False
        assert "TOKEN" in result["reason"]


class TestManageIssue:
    @patch("sdk_sync._find_open_issue")
    @patch("sdk_sync._ensure_label")
    @patch("sdk_sync._run_cmd")
    def test_create_new_issue(self, mock_run, mock_label, mock_find):
        mock_find.return_value = None
        mock_run.return_value = _mock_run(0, stdout="https://github.com/org/repo/issues/42\n")

        drift = {"sdk": "go", "synced": False, "files": [], "summary": "drifted"}
        result = manage_issue(drift, None, "go", "org/repo", "sdk-sync:go")
        assert result["action"] == "created"
        assert "42" in result["issue_url"]

    @patch("sdk_sync._find_open_issue")
    @patch("sdk_sync._ensure_label")
    @patch("sdk_sync._run_cmd")
    def test_update_existing_issue(self, mock_run, mock_label, mock_find):
        mock_find.return_value = {"url": "https://github.com/org/repo/issues/10", "number": "10"}
        mock_run.return_value = _mock_run(0)

        drift = {"sdk": "go", "synced": False, "files": [], "summary": "drifted"}
        result = manage_issue(drift, None, "go", "org/repo", "sdk-sync:go")
        assert result["action"] == "updated"
        assert "10" in result["issue_url"]


class TestFireDispatch:
    @patch("sdk_sync._run_cmd")
    def test_successful_dispatch(self, mock_run):
        mock_run.return_value = _mock_run(0)
        result = fire_dispatch("org/repo", "https://github.com/org/repo/issues/42", "go", "1 file(s) drifted")
        assert result["success"] is True

    @patch("sdk_sync._run_cmd")
    def test_dispatch_failure(self, mock_run):
        mock_run.return_value = _mock_run(1, stderr="permission denied")
        result = fire_dispatch("org/repo", "https://github.com/org/repo/issues/42", "go", "drifted")
        assert result["success"] is False
