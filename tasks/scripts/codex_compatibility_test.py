# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise the pinned SDK's public notification types without inference calls."""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import openai_codex
import pytest
from openai_codex.generated.v2_all import (
    ErrorNotification,
    ItemCompletedNotification,
    TurnCompletedNotification,
    TurnError,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))

import codex_compatibility as compatibility
from codex_compatibility_report import SURFACES

SENSITIVE = "PRIVATE_source_token_tool_output"
REVIEW = {
    "verdict": "no_unaddressed_breaks",
    "summary": "No changes to public contracts.",
    "reviewed_surfaces": list(SURFACES),
    "unreviewed_surfaces": [],
    "findings": [],
}


def turn_error(info):
    return TurnError(
        message=SENSITIVE,
        additionalDetails=SENSITIVE,
        codexErrorInfo=info,
    )


def completed(status="completed", error=None):
    return TurnCompletedNotification(
        threadId=SENSITIVE,
        turn={"id": "turn", "status": status, "error": error, "items": []},
    )


def message(text, phase="final_answer"):
    return ItemCompletedNotification(
        threadId=SENSITIVE,
        turnId="turn",
        completedAtMs=0,
        item={"type": "agentMessage", "id": "message", "text": text, "phase": phase},
    )


class FakeTurn:
    def __init__(self, events):
        self.events = events
        self.closed = False

    async def stream(self):
        try:
            for payload in self.events:
                if isinstance(payload, Exception):
                    raise payload
                yield SimpleNamespace(payload=payload)
        finally:
            self.closed = True


@pytest.fixture
def runner(monkeypatch, tmp_path):
    """Run the entire report pipeline with fake SDK I/O, not fake SDK types."""
    monkeypatch.setenv("NVIDIA_INFERENCE_API_KEY", SENSITIVE)
    monkeypatch.setattr(compatibility, "version", lambda _name: "0.160.0")
    monkeypatch.setattr(
        compatibility, "resolve_branch", lambda *_args: {"source_sha": "a" * 40}
    )
    monkeypatch.setattr(compatibility.subprocess, "run", lambda *_args, **_kwargs: None)

    def run(events, start_error=None):
        turn = FakeTurn(events)
        thread = SimpleNamespace(turn=AsyncMock(return_value=turn))
        codex = SimpleNamespace(
            thread_start=AsyncMock(return_value=thread, side_effect=start_error),
            close=AsyncMock(),
        )
        monkeypatch.setattr(
            compatibility.openai_codex, "AsyncCodex", lambda _config: codex
        )
        result = compatibility.run_review("candidate", "a" * 40, tmp_path, "base", 1)
        codex.close.assert_awaited_once()
        # Nothing unvalidated, including SDK messages or IDs, reaches artifacts.
        for artifact in tmp_path.iterdir():
            assert SENSITIVE not in artifact.read_text()
        assert json.loads((tmp_path / "report.json").read_text()) == result
        return result, turn

    return run


@pytest.mark.parametrize(
    ("info", "code", "status"),
    [
        ("rateLimitExceeded", "rateLimitExceeded", None),
        ("contextWindowExceeded", "contextWindowExceeded", None),
        (
            {"httpConnectionFailed": {"httpStatusCode": 429}},
            "httpConnectionFailed",
            429,
        ),
        (
            {"responseStreamConnectionFailed": {"httpStatusCode": 502}},
            "responseStreamConnectionFailed",
            502,
        ),
        (
            {"responseStreamDisconnected": {"httpStatusCode": 200}},
            "responseStreamDisconnected",
            200,
        ),
        (
            {"responseTooManyFailedAttempts": {"httpStatusCode": 503}},
            "responseTooManyFailedAttempts",
            503,
        ),
        (None, "unknown", None),
        (
            {"httpConnectionFailed": {"httpStatusCode": 999}},
            "httpConnectionFailed",
            None,
        ),
    ],
)
def test_failed_turn_retains_only_structured_error(runner, info, code, status):
    error = turn_error(info)
    notification = ErrorNotification(
        threadId=SENSITIVE, turnId="turn", error=error, willRetry=False
    )
    result, turn = runner([notification, completed("failed", error)])
    assert turn.closed
    assert result["status"] == "error"
    assert result["review"] is None
    diagnostics = result["diagnostics"]
    assert diagnostics["phase"] == "turn_stream"
    assert diagnostics["final_error"] == {"code": code, "http_status": status}
    assert diagnostics["last_error"] == diagnostics["final_error"]
    assert diagnostics["error_events"] == 1
    assert diagnostics["retry_events"] == 0
    assert diagnostics["turn_status"] == "failed"
    assert diagnostics["elapsed_seconds"] >= 0


def test_retry_can_recover_and_final_answer_wins(runner):
    notification = ErrorNotification(
        threadId=SENSITIVE,
        turnId="turn",
        error=turn_error("serverOverloaded"),
        willRetry=True,
    )
    result, turn = runner(
        [
            notification,
            message(SENSITIVE, "commentary"),
            message(json.dumps(REVIEW)),
            message(SENSITIVE, None),
            completed(),
        ]
    )
    assert turn.closed
    assert result["status"] == "complete"
    assert result["review"] == REVIEW
    diagnostics = result["diagnostics"]
    assert diagnostics["phase"] == "complete"
    assert diagnostics["turn_status"] == "completed"
    assert diagnostics["retry_events"] == 1
    assert "final_error" not in diagnostics


def test_unphased_final_answer_is_supported(runner):
    result, _turn = runner([message(json.dumps(REVIEW), None), completed()])
    assert result["review"] == REVIEW


def test_empty_final_answer_does_not_fall_back_to_earlier_text(runner):
    result, _turn = runner(
        [message(json.dumps(REVIEW), None), message(""), completed()]
    )
    assert result["status"] == "error"
    assert result["diagnostics"]["reason"] == "missing_final_response"


def test_incomplete_coverage_remains_incomplete(runner):
    review = {
        **REVIEW,
        "verdict": "needs_review",
        "reviewed_surfaces": list(SURFACES[1:]),
        "unreviewed_surfaces": [SURFACES[0]],
    }
    result, _turn = runner([message(json.dumps(review)), completed()])
    assert result["status"] == "incomplete"
    assert result["review"] == review
    assert result["diagnostics"]["phase"] == "complete"


@pytest.mark.parametrize("status", ["failed", "interrupted"])
def test_unsuccessful_turn_without_error_metadata(runner, status):
    result, _turn = runner([completed(status)])
    assert result["status"] == "error"
    assert result["diagnostics"]["turn_status"] == status
    assert "final_error" not in result["diagnostics"]


@pytest.mark.parametrize(
    ("events", "phase", "error_type"),
    [
        ([], "turn_stream", "ValueError"),
        ([completed()], "turn_stream", "ValueError"),
        ([RuntimeError(SENSITIVE)], "turn_stream", "RuntimeError"),
        ([TimeoutError()], "turn_stream", "TimeoutError"),
        ([message(SENSITIVE), completed()], "decode_report", "JSONDecodeError"),
        (
            [message(json.dumps({"summary": SENSITIVE})), completed()],
            "validate_report",
            "ValueError",
        ),
    ],
)
def test_failure_phase_and_no_unvalidated_output(runner, events, phase, error_type):
    result, turn = runner(events)
    assert turn.closed
    assert result["status"] == "error"
    assert result["diagnostics"]["phase"] == phase
    assert result["diagnostics"]["error_type"] == error_type


def test_rpc_failure_retains_numeric_code_not_message_or_data(runner):
    result, _turn = runner(
        [], openai_codex.JsonRpcError(-32602, SENSITIVE, {"data": SENSITIVE})
    )
    assert result["diagnostics"]["phase"] == "thread_start"
    assert result["diagnostics"]["rpc_code"] == -32602
    assert result["diagnostics"]["error_type"] == "JsonRpcError"


def test_merge_conflict_does_not_publish_subprocess_output(monkeypatch, tmp_path):
    def conflict(*_args):
        raise subprocess.CalledProcessError(
            1, ["git", "merge-tree", "--write-tree"], output=SENSITIVE, stderr=SENSITIVE
        )

    monkeypatch.setattr(compatibility, "resolve_branch", conflict)
    result = compatibility.run_review("candidate", "a" * 40, tmp_path, "base", 1)
    assert result["diagnostics"]["phase"] == "resolve_context"
    assert result["diagnostics"]["reason"] == "merge_conflict"
    assert result["diagnostics"]["exit_code"] == 1
    for artifact in tmp_path.iterdir():
        assert SENSITIVE not in artifact.read_text()


def test_unknown_error_codes_fail_closed():
    info = SimpleNamespace(
        model_dump=lambda **_kwargs: {SENSITIVE: {"httpStatusCode": 429}}
    )
    error = SimpleNamespace(codex_error_info=info)
    assert compatibility.public_turn_error(error) == {
        "code": "unknown",
        "http_status": None,
    }


@pytest.mark.parametrize(
    "status,exit_code", [("complete", 0), ("error", 1), ("incomplete", 1)]
)
def test_cli_exit_behavior_and_diagnostics(
    monkeypatch, capsys, tmp_path, status, exit_code
):
    monkeypatch.setattr(
        sys,
        "argv",
        ["codex_compatibility.py", "candidate", "--output-dir", str(tmp_path)],
    )
    monkeypatch.setattr(
        compatibility,
        "run_review",
        lambda *_args: {
            "status": status,
            "review": REVIEW if status != "error" else None,
            "diagnostics": {
                "phase": "complete" if status == "complete" else "turn_stream"
            },
        },
    )
    with pytest.raises(SystemExit) as caught:
        compatibility.main()
    assert caught.value.code == exit_code
    assert "Compatibility review execution diagnostics:" in capsys.readouterr().out
