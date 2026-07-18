# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from openshell._proto import openshell_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from openshell import Sandbox, SandboxClient


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
        # Server auto-generates a petname (e.g. "feasible-retriever")
        assert sb.sandbox.name
        parts = sb.sandbox.name.split("-")
        assert len(parts) == 2, (
            f"expected petname with 2 parts, got {sb.sandbox.name!r}"
        )
        assert all(p.isalpha() and p.islower() for p in parts)

        fetched = sandbox_client.get(sb.sandbox.name)
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


def test_sandbox_interactive_exec_honors_tty(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    stdin_sentinel = b"streamed-stdin-sentinel"
    stdout_sentinel = b"stdout-sentinel"
    stderr_sentinel = b"stderr-sentinel"

    def exec_interactive(sandbox_id: str, *, tty: bool) -> tuple[bytes, bytes]:
        request = openshell_pb2.ExecSandboxInput(
            start=openshell_pb2.ExecSandboxRequest(
                sandbox_id=sandbox_id,
                command=[
                    "/bin/sh",
                    "-c",
                    "[ -t 0 ] && printf T || printf N; "
                    "[ -t 1 ] && printf T || printf N; "
                    "[ -t 2 ] && printf T || printf N; printf '\\n'; "
                    "IFS= read -r stdin_value; "
                    "printf 'stdin:%s\\n' \"$stdin_value\"; "
                    "printf 'stdout-sentinel\\n'; "
                    "printf 'stderr-sentinel\\n' >&2",
                ],
                tty=tty,
                timeout_seconds=20,
            )
        )

        done = threading.Event()

        def requests():
            yield request
            yield openshell_pb2.ExecSandboxInput(stdin=stdin_sentinel + b"\n")
            done.wait(timeout=30)

        stdout: list[bytes] = []
        stderr: list[bytes] = []
        exit_code: int | None = None
        try:
            events = sandbox_client._stub.ExecSandboxInteractive(requests(), timeout=30)
            for event in events:
                payload = event.WhichOneof("payload")
                if payload == "stdout":
                    stdout.append(bytes(event.stdout.data))
                elif payload == "stderr":
                    stderr.append(bytes(event.stderr.data))
                elif payload == "exit":
                    exit_code = int(event.exit.exit_code)
        finally:
            done.set()

        assert exit_code == 0
        return b"".join(stdout), b"".join(stderr)

    with sandbox(delete_on_exit=True) as sb:
        stdout, stderr = exec_interactive(sb.id, tty=False)
        assert b"NNN" in stdout
        assert b"stdin:" + stdin_sentinel in stdout
        assert stdout_sentinel in stdout
        assert stdout_sentinel not in stderr
        assert stderr_sentinel in stderr
        assert stderr_sentinel not in stdout

        stdout, stderr = exec_interactive(sb.id, tty=True)
        assert b"TTT" in stdout + stderr


def test_sandbox_labels_and_selectors(sandbox_client: SandboxClient) -> None:
    import contextlib
    import uuid

    suffix = uuid.uuid4().hex[:8]
    job_a = f"aiq-labels-a-{suffix}"
    job_b = f"aiq-labels-b-{suffix}"
    group_selector = f"aiq-test={suffix}"
    primary_selector = f"aiq-test={suffix},role=primary"

    created: list[str] = []
    try:
        ref_a = sandbox_client.create(
            name=job_a, labels={"aiq-test": suffix, "role": "primary"}
        )
        created.append(ref_a.name)
        ref_b = sandbox_client.create(
            name=job_b, labels={"aiq-test": suffix, "role": "secondary"}
        )
        created.append(ref_b.name)

        # Labels round-trip through create and get.
        assert ref_a.labels["role"] == "primary"
        assert dict(sandbox_client.get(job_a).labels)["role"] == "primary"
        assert dict(sandbox_client.get(job_b).labels)["role"] == "secondary"

        # A specific selector filters to exactly the primary sandbox.
        assert {
            s.name for s in sandbox_client.list(label_selector=primary_selector)
        } == {job_a}
        # The shared group label returns both.
        assert {s.name for s in sandbox_client.list(label_selector=group_selector)} == {
            job_a,
            job_b,
        }

        # Deleting one removes only it from selector results.
        assert sandbox_client.delete(job_a)
        sandbox_client.wait_deleted(job_a)
        created.remove(job_a)
        assert {s.name for s in sandbox_client.list(label_selector=group_selector)} == {
            job_b
        }

        # Final deletion leaves no matching sandboxes.
        assert sandbox_client.delete(job_b)
        sandbox_client.wait_deleted(job_b)
        created.remove(job_b)
        assert not sandbox_client.list(label_selector=group_selector)
    finally:
        for name in created:
            with contextlib.suppress(Exception):
                sandbox_client.delete(name)
