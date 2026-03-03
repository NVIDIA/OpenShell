# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from navigator import Sandbox, SandboxClient


def test_sandbox_api_crud_and_exec(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    class _FileOps:
        def write(self, path: str, content: str) -> None:
            from pathlib import Path

            Path(path).write_text(content)

        def read(self, path: str) -> str:
            from pathlib import Path

            return Path(path).read_text()

    with sandbox(delete_on_exit=True) as sb:
        assert sb.id
        assert sb.sandbox.name.startswith("sandbox-")

        fetched = sandbox_client.get(sb.id)
        assert fetched.id == sb.id

        ids = set(sandbox_client.list_ids(limit=100))
        assert sb.id in ids

        result = sb.exec(["python", "-c", "print('sandbox-ok')"])
        assert result.exit_code == 0
        assert "sandbox-ok" in result.stdout

        file_ops = _FileOps()
        create_file = sb.exec_python(
            file_ops.write,
            args=("/sandbox/exec-persistence.txt", "ok"),
        )
        assert create_file.exit_code == 0

        verify_file = sb.exec_python(
            file_ops.read, args=("/sandbox/exec-persistence.txt",)
        )
        assert verify_file.exit_code == 0
        assert verify_file.stdout.strip() == "ok"
