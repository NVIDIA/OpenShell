# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for tasks/scripts/sdk_sync.py.

Run via: uv run --no-project --with pytest pytest tasks/scripts/sdk_sync_test.py
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

from sdk_sync import (
    generate_issue_body,
    manage_issue,
)


def _mock_run(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


class TestGenerateIssueBody:
    def test_go_sdk_issue_body(self):
        drift = {
            "sdk": "go",
            "synced": False,
            "files": [
                {
                    "name": "openshellv1/openshell.pb.go",
                    "status": "modified",
                    "diff_lines": 5,
                }
            ],
            "summary": "1 file(s) drifted",
        }
        md = generate_issue_body(drift, None, "go")
        assert "## Proto Drift Report" in md
        assert "`openshellv1/openshell.pb.go`" in md
        assert "## Fix Commands" in md
        assert "mise run go:proto:gen" in md

    def test_typescript_sdk_issue_body(self):
        drift = {
            "sdk": "typescript",
            "synced": False,
            "files": [],
            "summary": "typecheck failed after proto regeneration",
        }
        md = generate_issue_body(drift, None, "typescript")
        assert "mise run sdk:ts:proto" in md
        assert "mise run sdk:ts:build" in md
        assert "mise run sdk:ts:test" in md
        assert "sdk/typescript/src/" in md
        assert "not individually tracked" in md
        assert "mise run sdk:ts:proto && mise run sdk:ts:typecheck" in md

    def test_with_build_log(self):
        drift = {"sdk": "go", "synced": False, "files": [], "summary": "drifted"}
        build = {
            "sdk": "go",
            "success": False,
            "failed_step": "build",
            "log": "error here",
        }
        md = generate_issue_body(drift, build, "go")
        assert "## Build Log" in md
        assert "`build`" in md
        assert "error here" in md

    def test_log_truncation(self):
        long_log = "\n".join(f"line {i}" for i in range(1000))
        drift = {"sdk": "go", "synced": False, "files": [], "summary": "drifted"}
        build = {
            "sdk": "go",
            "success": False,
            "failed_step": "test",
            "log": long_log,
        }
        md = generate_issue_body(drift, build, "go", max_log_lines=500)
        log_section = md.split("```")[1]
        assert log_section.strip().count("\n") <= 500
        assert "line 999" in md
        assert "line 0" not in md

    def test_agent_instructions_present(self):
        drift = {
            "sdk": "go",
            "synced": False,
            "files": [
                {
                    "name": "openshellv1/openshell.pb.go",
                    "status": "modified",
                    "diff_lines": 5,
                }
            ],
            "summary": "1 file(s) drifted",
        }
        build = {
            "sdk": "go",
            "success": False,
            "failed_step": "build",
            "log": "error",
        }
        md = generate_issue_body(drift, build, "go")
        assert "## Agent Instructions" in md
        assert "Agent prompt" in md
        assert "mise run go:proto:gen" in md
        assert "sdk/go/openshell/v1/internal/converter/" in md
        assert "sdk/go/openshell/v1/types/" in md
        assert "sdk/go/openshell/v1/" in md
        assert "Create a PR" in md

    def test_agent_instructions_includes_failed_step(self):
        drift = {"sdk": "go", "synced": False, "files": [], "summary": "drifted"}
        build = {
            "sdk": "go",
            "success": False,
            "failed_step": "test",
            "log": "fail",
        }
        md = generate_issue_body(drift, build, "go")
        agent_section = md.split("## Agent Instructions")[1]
        assert "`test`" in agent_section
        assert "fails at" in agent_section.lower()


class TestManageIssue:
    @patch("sdk_sync._find_open_issue")
    @patch("sdk_sync._ensure_label")
    @patch("sdk_sync._run_cmd")
    def test_create_new_issue(self, mock_run, _mock_label, mock_find):
        mock_find.return_value = None
        mock_run.return_value = _mock_run(
            0, stdout="https://github.com/org/repo/issues/42\n"
        )

        drift = {"sdk": "go", "synced": False, "files": [], "summary": "drifted"}
        result = manage_issue(drift, None, "go", "org/repo", "sdk:go:sync")
        assert result["action"] == "created"
        assert "42" in result["issue_url"]

    @patch("sdk_sync._find_open_issue")
    @patch("sdk_sync._ensure_label")
    @patch("sdk_sync._run_cmd")
    def test_update_existing_issue(self, mock_run, _mock_label, mock_find):
        mock_find.return_value = {
            "url": "https://github.com/org/repo/issues/10",
            "number": "10",
        }
        mock_run.return_value = _mock_run(0)

        drift = {"sdk": "go", "synced": False, "files": [], "summary": "drifted"}
        result = manage_issue(drift, None, "go", "org/repo", "sdk:go:sync")
        assert result["action"] == "updated"
        assert "10" in result["issue_url"]
