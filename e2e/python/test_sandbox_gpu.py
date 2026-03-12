# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from openshell._proto import datamodel_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from openshell import Sandbox


@pytest.mark.gpu
def test_gpu_sandbox_reports_available_gpu(
    sandbox: Callable[..., Sandbox],
    gpu_sandbox_spec: datamodel_pb2.SandboxSpec,
) -> None:
    with sandbox(spec=gpu_sandbox_spec, delete_on_exit=True) as sb:
        result = sb.exec(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            timeout_seconds=30,
        )

        assert result.exit_code == 0, result.stderr
        assert result.stdout.strip()
