# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""SDK sync regression tests. Run via: mise run test:sdk-sync."""

from __future__ import annotations

import json
import os
import subprocess
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from sdk_sync import cmd_manage_issue, generate_issue_body

ISSUE = {"number": 42, "url": "https://github.com/org/repo/issues/42"}
LABELS = [{"name": "SDK:GO:SYNC"}]


def _response(stdout="", code=0, stderr=""):
    return subprocess.CompletedProcess([], code, stdout=stdout, stderr=stderr)


@pytest.fixture
def drift():
    return {
        "sdk": "go",
        "synced": False,
        "summary": "1 file drifted",
        "files": [{"name": "openshell.pb.go", "status": "modified", "diff_lines": 5}],
    }


@pytest.fixture
def issue_args(drift):
    return Namespace(
        sdk="go",
        repo="org/repo",
        label="sdk:go:sync",
        drift_report=json.dumps(drift),
        build_report='{"success":true}',
    )


@pytest.mark.parametrize(
    ("sdk", "success", "context"),
    [
        ("go", None, "build status is unknown"),
        ("typescript", None, "not individually tracked"),
        ("go", True, "committed bindings still need to be regenerated and committed"),
        ("typescript", True, "gitignored"),
        ("go", False, "fails at the `build` step"),
    ],
)
def test_issue_body(drift, sdk, success, context):
    report = {**drift, "sdk": sdk, "files": drift["files"] if sdk == "go" else []}
    build = (
        None
        if success is None
        else {
            "success": success,
            "failed_step": None if success else "build",
            "log": "compiler error",
        }
    )
    body = generate_issue_body(report, build, sdk)

    assert context in body
    assert "## Agent Instructions" in body
    assert "Create a PR" in body
    assert f"sdk/{sdk}/" in body
    assert ("## Build Log" in body) == (success is False)
    if sdk == "go":
        assert "| `openshell.pb.go` | modified | 5 |" in body
        assert "mise run go:proto:gen" in body
    else:
        assert "mise run sdk:ts:proto" in body
    if success is False:
        assert "compiler error" in body


def test_build_log_keeps_only_the_last_lines(drift):
    build = {"failed_step": "test", "log": "discarded\nretained\nlast line"}
    body = generate_issue_body(drift, build, "go", max_log_lines=2)
    assert "discarded" not in body
    assert "retained\nlast line" in body


@pytest.mark.parametrize("labels", [LABELS, [{"name": "area:sdk:go"}]])
def test_create_then_update_preserves_label_and_issue(
    issue_args, drift, labels, capsys
):
    """Exercise all lifecycle helpers; mock only the GitHub subprocesses."""
    missing_label = labels != LABELS
    responses = [_response(json.dumps(labels))]
    operations = ["label list"]
    if missing_label:
        responses.append(_response())
        operations.append("label create")
    responses += [
        _response("[]"),
        _response(ISSUE["url"]),
        _response(json.dumps(LABELS)),
        _response(json.dumps([ISSUE])),
        _response(),
    ]
    operations += [
        "issue list",
        "issue create",
        "label list",
        "issue list",
        "issue edit",
    ]

    with patch("sdk_sync.subprocess.run", side_effect=responses) as github:
        for action in ["created", "updated"]:
            issue_args.drift_report = json.dumps({**drift, "summary": action})
            assert cmd_manage_issue(issue_args) == 0
            assert json.loads(capsys.readouterr().out) == {
                "action": action,
                "issue_url": ISSUE["url"],
            }
            cmd = github.call_args.args[0]
            assert cmd[cmd.index("--body-file") + 1] == "-"
            assert f"**Summary**: {action}" in github.call_args.kwargs["input"]

    assert [" ".join(call.args[0][1:3]) for call in github.call_args_list] == operations
    assert github.call_args.args[0][3] == str(ISSUE["number"])


@pytest.mark.parametrize(
    ("before", "failure"),
    [
        ([], _response(code=1, stderr="API unavailable")),
        ([], _response("invalid JSON")),
        ([], _response('[{"name":null}]')),
        ([], _response(json.dumps([{"name": f"other-{i}"} for i in range(20)]))),
        ([_response("[]")], _response(code=1, stderr="label creation denied")),
        ([_response(json.dumps(LABELS))], _response(code=1, stderr="API unavailable")),
        ([_response(json.dumps(LABELS))], _response("invalid JSON")),
        ([_response(json.dumps(LABELS))], _response("null")),
        ([_response(json.dumps(LABELS))], _response('[{"url":"url","number":true}]')),
    ],
)
def test_lookup_errors_stop_before_issue_mutation(issue_args, capsys, before, failure):
    with patch("sdk_sync.subprocess.run", side_effect=[*before, failure]) as github:
        assert cmd_manage_issue(issue_args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["action"] == "error"
    assert result["reason"]
    assert github.call_count == len(before) + 1
    assert all(
        call.args[0][1:3] not in [["issue", "create"], ["issue", "edit"]]
        for call in github.call_args_list
    )


def test_timeout_returns_an_error_without_retrying(issue_args, capsys):
    with patch(
        "sdk_sync.subprocess.run", side_effect=subprocess.TimeoutExpired("gh", 60)
    ) as github:
        assert cmd_manage_issue(issue_args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["action"] == "error"
    assert "timed out after 60 seconds" in result["reason"]
    github.assert_called_once()
    assert github.call_args.kwargs["timeout"] == 60


@pytest.mark.parametrize(
    ("field", "value"), [("drift_report", "invalid JSON"), ("build_report", "[]")]
)
def test_invalid_reports_never_call_github(issue_args, capsys, field, value):
    setattr(issue_args, field, value)
    with patch("sdk_sync.subprocess.run") as github:
        assert cmd_manage_issue(issue_args) == 1
        github.assert_not_called()
    assert json.loads(capsys.readouterr().out)["action"] == "error"


@pytest.fixture
def dashboard():
    path = (
        Path(__file__).resolve().parents[2] / ".github/workflows/sdk-sync-dashboard.yml"
    )
    return yaml.safe_load(path.read_text())["jobs"]


def _step(dashboard, job, name):
    return next(step for step in dashboard[job]["steps"] if step.get("name") == name)


def _run_shell(tmp_path, script, **env):
    script = script.replace("${{ matrix.sdk.name }}", "go").replace(
        "${{ matrix.sdk.label }}", "sdk:go:sync"
    )
    return subprocess.run(
        ["sh", "-e"],
        input=script,
        cwd=tmp_path,
        text=True,
        capture_output=True,
        env={**os.environ, "GITHUB_REPOSITORY": "org/repo", **env},
    )


@pytest.mark.parametrize(
    ("report", "build_exit", "expected"),
    [
        ('{"synced":true}', "0", "false"),
        ('{"synced":false}', "0", "true"),
        ('{"synced":false}', "1", "true"),
        ('{"synced":false,"error":"generation failed"}', "0", "error"),
        ("invalid JSON", "0", "error"),
    ],
)
def test_workflow_classifies_drift(dashboard, tmp_path, report, build_exit, expected):
    step = _step(dashboard, "sdk_sync_check", "Check proto drift and build")
    stub = """mise() {
      if [ "$2" = drift ]; then printf '%s\\n' "$REPORT"; return 1; fi
      printf '%s\\n' '{}'
      return "$BUILD_EXIT"
    }
    """
    result = _run_shell(
        tmp_path,
        stub + step["run"],
        SDK_NAME="go",
        DRIFT_TASK="drift",
        BUILD_CHECK_TASK="build",
        REPORT=report,
        BUILD_EXIT=build_exit,
    )
    assert result.returncode == 0, result.stderr
    status = json.loads((tmp_path / "report/status.json").read_text())
    assert status["has_drift"] == expected
    assert status["build_failed"] == (
        "true" if expected == "true" and build_exit == "1" else "false"
    )


@pytest.mark.parametrize(
    ("output", "code", "succeeds"),
    [
        ('{"action":"created"}', "0", True),
        ('{"action":"updated"}', "0", True),
        ('{"action":"error"}', "1", False),
        ("invalid JSON", "0", False),
        ("", "0", False),
        ('{"action":"unexpected"}', "0", False),
    ],
)
def test_workflow_requires_successful_issue_result(
    dashboard, tmp_path, output, code, succeeds
):
    step = _step(dashboard, "issue_management", "Create or update drift issue")
    report = tmp_path / "report"
    report.mkdir()
    for name in ["drift", "build"]:
        (report / f"{name}.json").write_text("{}")
    stub = 'uv() { printf \'%s\\n\' "$OUTPUT"; return "$CODE"; }\n'
    result = _run_shell(tmp_path, stub + step["run"], OUTPUT=output, CODE=code)
    assert (result.returncode == 0) == succeeds, result.stdout + result.stderr


@pytest.mark.parametrize(("number", "code"), [("42", "0"), ("", "0"), ("", "1")])
def test_workflow_closes_resolved_issue(dashboard, tmp_path, number, code):
    step = _step(dashboard, "issue_management", "Close resolved drift issue")
    stub = """gh() {
      if [ "$2" = list ]; then printf '%s\\n' "$NUMBER"; return "$CODE"; fi
      [ "$2" = close ] && [ "$3" = 42 ] || return 9
      printf 'closed\\n' > closed
    }
    """
    result = _run_shell(tmp_path, stub + step["run"], NUMBER=number, CODE=code)
    assert result.returncode == int(code)
    assert (tmp_path / "closed").exists() == bool(number)


def test_workflow_gates_issue_lifecycle_on_drift(dashboard):
    steps = dashboard["issue_management"]["steps"]
    checkout = next(
        step for step in steps if step.get("uses", "").startswith("actions/checkout@")
    )
    assert "if" not in checkout
    for name in ["Install tools", "Create or update drift issue"]:
        assert (
            _step(dashboard, "issue_management", name)["if"]
            == "steps.status.outputs.has_drift == 'true'"
        )
    assert (
        _step(dashboard, "issue_management", "Close resolved drift issue")["if"]
        == "steps.status.outputs.has_drift == 'false'"
    )
