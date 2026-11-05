# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import openai_codex
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import codex_compatibility as compatibility


@pytest.mark.parametrize(
    "error_type", [RuntimeError, ValueError, openai_codex.CodexError]
)
@pytest.mark.parametrize("long_message", [False, True])
def test_sdk_error_message_is_retained_redacted_and_bounded(
    monkeypatch, tmp_path, error_type, long_message
):
    secrets = ["inference-secret", "gh-secret", "github-secret", "codex-secret"]
    for key, secret in zip(
        (
            "NVIDIA_INFERENCE_API_KEY",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "CODEX_SECURITY_API_KEY",
        ),
        secrets,
        strict=True,
    ):
        monkeypatch.setenv(key, secret)
    message = "HTTP 502\nresponse stream disconnected " + " ".join(secrets)
    if long_message:
        message += "x" * 2000
    thread = SimpleNamespace(run=AsyncMock(side_effect=error_type(message)))
    codex = SimpleNamespace(
        thread_start=AsyncMock(return_value=thread), close=AsyncMock()
    )
    monkeypatch.setattr(compatibility.openai_codex, "AsyncCodex", lambda _config: codex)
    monkeypatch.setattr(compatibility.subprocess, "run", lambda *_args, **_kwargs: None)

    with pytest.raises(ValueError) as caught:
        asyncio.run(compatibility.invoke_codex({}, tmp_path))

    error = str(caught.value)
    assert (
        f"Codex SDK review failed ({error_type.__name__}): HTTP 502 response stream disconnected"
        in error
    )
    assert all(secret not in error for secret in secrets)
    assert error.count("[REDACTED]") == 4
    detail = error.split(": ", 1)[1].removesuffix("; no assessment is available.")
    assert len(detail) <= 1000
    assert "\n" not in error
    codex.close.assert_awaited_once()
