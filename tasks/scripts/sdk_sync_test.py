# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""SDK sync regression tests. Run via: mise run test:sdk-sync."""

from __future__ import annotations

import json
import os
import subprocess
import tomllib
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest
import sdk_sync
import yaml
from sdk_sync import _load_json_arg, cmd_manage_issue, generate_issue_body, main

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


def test_issue_body_uses_config_for_an_unlisted_sdk(drift, monkeypatch):
    monkeypatch.setitem(
        sdk_sync.SDK_CONFIGS,
        "python",
        {
            "name": "python",
            "display_name": "Python",
            "bindings_committed": False,
            "no_file_tracking_hint": "tracked by the Python package build",
            "generated_bindings_status": "gitignored",
            "proto_task": "python:proto:gen",
            "drift_task": "python:proto:drift",
            "build_task": "python:build",
            "test_task": "python:test",
            "source_dirs": ["python/openshell/"],
        },
    )

    body = generate_issue_body(
        {**drift, "files": []},
        {"success": True},
        "python",
    )

    assert "tracked by the Python package build" in body
    assert "The subsequent regeneration, build, and tests passed in CI." in body
    assert "mise run python:proto:gen" in body


def test_build_log_keeps_only_the_last_lines(drift):
    build = {"failed_step": "test", "log": "discarded\nretained\nlast line"}
    body = generate_issue_body(drift, build, "go", max_log_lines=2)
    assert "discarded" not in body
    assert "retained\nlast line" in body


def test_build_log_has_a_character_limit(drift):
    body = generate_issue_body(
        drift,
        {"failed_step": "build", "log": "x" * 20000},
        "go",
    )
    assert len(body) < 20000
    assert "[... build log truncated ...]" in body


def test_build_log_character_limit_handles_small_budget(drift):
    body = generate_issue_body(
        drift,
        {"failed_step": "build", "log": "x" * 20000},
        "go",
        max_log_chars=5,
    )
    log = body.split("```\n", 1)[1].split("\n```", 1)[0]
    assert len(log) == 5


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


def test_issue_create_failure_is_structured(issue_args, capsys):
    responses = [
        _response(json.dumps(LABELS)),
        _response("[]"),
        _response(code=1, stderr="permission denied"),
    ]
    with patch("sdk_sync.subprocess.run", side_effect=responses):
        assert cmd_manage_issue(issue_args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["action"] == "error"
    assert "permission denied" in result["reason"]


def test_issue_edit_failure_is_structured(issue_args, capsys):
    responses = [
        _response(json.dumps(LABELS)),
        _response(json.dumps([ISSUE])),
        _response(code=1, stderr="rate limited"),
    ]
    with patch("sdk_sync.subprocess.run", side_effect=responses):
        assert cmd_manage_issue(issue_args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["action"] == "error"
    assert "rate limited" in result["reason"]


def test_issue_update_closes_duplicate_issues(issue_args, capsys):
    duplicate = {"number": 43, "url": "https://github.com/org/repo/issues/43"}
    responses = [
        _response(json.dumps(LABELS)),
        _response(json.dumps([ISSUE, duplicate])),
        _response(),
        _response(),
    ]
    with patch("sdk_sync.subprocess.run", side_effect=responses) as github:
        assert cmd_manage_issue(issue_args) == 0
    assert json.loads(capsys.readouterr().out) == {
        "issue_url": ISSUE["url"],
        "action": "updated",
    }
    assert github.call_args_list[-1].args[0][1:3] == ["issue", "close"]


def test_issue_list_limit_fails_closed(issue_args, capsys):
    issues = [
        {"number": number, "url": f"https://github.com/org/repo/issues/{number}"}
        for number in range(1, 102)
    ]
    responses = [_response(json.dumps(LABELS)), _response(json.dumps(issues))]
    with patch("sdk_sync.subprocess.run", side_effect=responses) as github:
        assert cmd_manage_issue(issue_args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["action"] == "error"
    assert "truncated" in result["reason"]
    assert github.call_count == 2


def test_load_json_arg_supports_stdin():
    with patch("sdk_sync.sys.stdin") as stdin:
        stdin.read.return_value = '{"key": "value"}'
        assert _load_json_arg("-") == {"key": "value"}


def test_load_json_arg_rejects_invalid_stdin():
    with patch("sdk_sync.sys.stdin") as stdin:
        stdin.read.return_value = "invalid JSON"
        with pytest.raises(json.JSONDecodeError):
            _load_json_arg("-")


def test_main_dispatches_manage_issue(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "sdk_sync.py",
            "manage-issue",
            "--drift-report",
            '{"synced": false}',
            "--sdk",
            "go",
            "--repo",
            "org/repo",
            "--label",
            "sdk:go:sync",
        ],
    )
    with patch("sdk_sync.manage_issue", return_value={"action": "created"}) as manage:
        assert main() == 0
    manage.assert_called_once()


@pytest.fixture
def dashboard():
    path = (
        Path(__file__).resolve().parents[2] / ".github/workflows/sdk-sync-dashboard.yml"
    )
    return yaml.safe_load(path.read_text())["jobs"]


@pytest.fixture
def proto_workflow():
    path = (
        Path(__file__).resolve().parents[2]
        / ".github/workflows/sdk-proto-check.yml"
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
        ('{"synced":true}', "0", "error"),
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


def test_workflow_rejects_report_with_inconsistent_exit_status(
    proto_workflow, tmp_path
):
    step = _step(proto_workflow, "sdk_proto_drift", "Check proto drift")
    output = tmp_path / "github-output"
    stub = """mise() {
      printf '%s\\n' '{"synced":true}'
      return 2
    }
    """
    result = _run_shell(
        tmp_path,
        stub + step["run"],
        DRIFT_TASK="drift",
        GITHUB_OUTPUT=str(output),
        RUNNER_TEMP=str(tmp_path),
    )
    assert result.returncode == 1, result.stderr
    assert "synced=error" in output.read_text()


def test_typescript_drift_reports_generation_errors():
    path = Path(__file__).resolve().parents[2] / "tasks/typescript.toml"
    task = tomllib.loads(path.read_text())["sdk:ts:proto:drift"]["run"]
    result = subprocess.run(
        ["bash", "-e"],
        input="mise() { return 1; }\n" + task,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["error"] == "proto generation failed"


def test_prepare_go_buf_template_escapes_windows_output_path(tmp_path):
    sdk_root = tmp_path / "sdk"
    work_dir = tmp_path / "work"
    sdk_root.mkdir()
    work_dir.mkdir()
    (sdk_root / "buf.gen.yaml").write_text(
        "version: v2\nplugins:\n  - local: protoc-gen-go\n    out: sdk/go\n"
    )
    script = f"""
source tasks/scripts/prepare_go_buf_template.sh
cygpath() {{
  if [ "$1" = "-m" ]; then
    printf '%s\\n' 'C:/runner/a&b'
  fi
}}
protoc-gen-go() {{ :; }}
protoc-gen-go-grpc() {{ :; }}
prepare_go_buf_template '{sdk_root}' '{work_dir}' >/dev/null
cat '{work_dir}/buf.gen.yaml'
"""
    result = subprocess.run(
        ["bash", "-e"],
        input=script,
        cwd=Path(__file__).resolve().parents[2],
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert "out: C:/runner/a&b" in result.stdout


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
    assert dashboard["issue_management"]["if"] == (
        "always() && needs.load_config.result == 'success'"
    )
