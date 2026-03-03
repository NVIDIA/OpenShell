# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from navigator import Sandbox


def test_exec_python_accepts_bound_methods(
    sandbox: Callable[..., Sandbox],
) -> None:
    class _Calculator:
        def multiply(self, left: int, right: int) -> int:
            return left * right

    with sandbox(delete_on_exit=True) as sb:
        calculator = _Calculator()
        result = sb.exec_python(calculator.multiply, args=(6, 7), timeout_seconds=20)

        assert result.exit_code == 0
        assert result.stdout.strip() == "42"


def test_exec_python_surfaces_callable_errors(
    sandbox: Callable[..., Sandbox],
) -> None:
    class _Boom:
        def fail(self) -> None:
            raise RuntimeError("expected-failure")

    with sandbox(delete_on_exit=True) as sb:
        result = sb.exec_python(_Boom().fail, timeout_seconds=20)

        assert result.exit_code != 0
        output = f"{result.stdout}\n{result.stderr}"
        assert "expected-failure" in output
        assert "RuntimeError" in output
