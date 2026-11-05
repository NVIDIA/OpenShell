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
def test_sdk_error_message_is_retained(monkeypatch, tmp_path, error_type):
    message = "HTTP 502: response stream disconnected"
    thread = SimpleNamespace(run=AsyncMock(side_effect=error_type(message)))
    codex = SimpleNamespace(
        thread_start=AsyncMock(return_value=thread), close=AsyncMock()
    )
    monkeypatch.setattr(compatibility.openai_codex, "AsyncCodex", lambda _config: codex)
    monkeypatch.setattr(compatibility.subprocess, "run", lambda *_args, **_kwargs: None)

    with pytest.raises(ValueError) as caught:
        asyncio.run(compatibility.invoke_codex({}, tmp_path))

    assert str(caught.value) == (
        f"Codex SDK review failed ({error_type.__name__}): {message}; no assessment is available."
    )
    codex.close.assert_awaited_once()
