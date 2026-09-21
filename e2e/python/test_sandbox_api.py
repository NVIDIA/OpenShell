# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import contextlib
import threading
import uuid
from typing import TYPE_CHECKING

from google.protobuf import duration_pb2

from openshell._proto import datamodel_pb2, openshell_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from openshell import Sandbox, SandboxClient, WorkspaceClient


def test_mutation_replay_preserves_sandbox_lifecycle_and_replacement(
    sandbox_client: SandboxClient,
) -> None:
    name = f"replay-{uuid.uuid4().hex[:8]}"
    scope = "default"
    stub = sandbox_client._stub
    create = openshell_pb2.CreateSandboxRequest(
        name=name,
        spec=openshell_pb2.SandboxSpec(),
        workspace_scope=datamodel_pb2.WorkspaceSelector(workspace=scope),
        request_id=str(uuid.uuid4()),
    )

    def replay(method, request):
        result, call = method.with_call(request, timeout=60)
        assert dict(call.initial_metadata())["openshell-replayed"] == "true"
        return result

    try:
        original = stub.CreateSandbox(create, timeout=60).sandbox.metadata.id
        sandbox_client.wait_ready(name, workspace="default", timeout_seconds=300)
        assert replay(stub.CreateSandbox, create).sandbox.metadata.id == original
        stop = openshell_pb2.StopSandboxRequest(
            name=name,
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace=scope),
            request_id=str(uuid.uuid4()),
        )
        stub.StopSandbox(stop, timeout=60)
        sandbox_client.wait_stopped(name, workspace="default", timeout_seconds=120)
        assert replay(stub.StopSandbox, stop).sandbox.metadata.id == original
        start = openshell_pb2.StartSandboxRequest(
            name=name,
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace=scope),
            request_id=str(uuid.uuid4()),
        )
        stub.StartSandbox(start, timeout=60)
        sandbox_client.wait_ready(name, workspace="default", timeout_seconds=300)
        assert replay(stub.StartSandbox, start).sandbox.metadata.id == original
        update = openshell_pb2.UpdateConfigRequest(
            sandbox=name,
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace=scope),
            setting_key="ocsf_json_enabled",
            setting_value=sandbox_pb2.SettingValue(bool_value=True),
            request_id=str(uuid.uuid4()),
        )
        updated = stub.UpdateConfig(update, timeout=30)
        assert replay(stub.UpdateConfig, update) == updated
        delete = openshell_pb2.DeleteSandboxRequest(
            name=name,
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace=scope),
            request_id=str(uuid.uuid4()),
        )
        deleted = stub.DeleteSandbox(delete, timeout=60)
        assert deleted.sandbox_id == original
        sandbox_client.wait_deleted(name, workspace="default", timeout_seconds=120)
        replacement = sandbox_client.create(workspace="default", name=name)
        assert replacement.id != original
        assert replay(stub.DeleteSandbox, delete) == deleted
        assert sandbox_client.get(name, workspace="default").id == replacement.id
    finally:
        with contextlib.suppress(Exception):
            sandbox_client.delete(name, workspace="default", allow_missing=True)
            sandbox_client.wait_deleted(name, workspace="default", timeout_seconds=120)


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

        fetched = sandbox_client.get(sb.sandbox.name, workspace="default")
        assert fetched.id == sb.id

        ids = set(sandbox_client.list_ids(workspace="default", page_size=100))
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

    def exec_interactive(sandbox_name: str, *, tty: bool) -> tuple[bytes, bytes]:
        request = openshell_pb2.ExecSandboxInput(
            start=openshell_pb2.ExecSandboxRequest(
                sandbox=sandbox_name,
                workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default"),
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
                execution_timeout=duration_pb2.Duration(seconds=20),
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
        stdout, stderr = exec_interactive(sb.sandbox.name, tty=False)
        assert b"NNN" in stdout
        assert b"stdin:" + stdin_sentinel in stdout
        assert stdout_sentinel in stdout
        assert stdout_sentinel not in stderr
        assert stderr_sentinel in stderr
        assert stderr_sentinel not in stdout

        stdout, stderr = exec_interactive(sb.sandbox.name, tty=True)
        assert b"TTT" in stdout + stderr


def test_interactive_exec_drains_output_after_request_eof(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    with sandbox(delete_on_exit=True) as sb:

        def requests():
            yield openshell_pb2.ExecSandboxInput(
                start=openshell_pb2.ExecSandboxRequest(
                    sandbox=sb.sandbox.name,
                    workspace_scope=datamodel_pb2.WorkspaceSelector(workspace="default"),
                    command=[
                        "/bin/sh",
                        "-c",
                        "input=$(cat); sleep 0.2; "
                        "printf '%s' \"$input\"; printf 'drained-stderr' >&2; exit 7",
                    ],
                    tty=False,
                    execution_timeout=duration_pb2.Duration(seconds=20),
                )
            )
            yield openshell_pb2.ExecSandboxInput(stdin=b"drained-stdout")
            # End requests before the command emits output. The receive
            # direction must survive long enough to drain both output streams.

        stdout = bytearray()
        stderr = bytearray()
        exit_codes: list[int] = []
        for event in sandbox_client._stub.ExecSandboxInteractive(
            requests(), timeout=30
        ):
            assert not exit_codes, "received another event after terminal exit"
            payload = event.WhichOneof("payload")
            if payload == "stdout":
                stdout.extend(event.stdout.data)
            elif payload == "stderr":
                stderr.extend(event.stderr.data)
            elif payload == "exit":
                exit_codes.append(event.exit.exit_code)
        assert stdout == b"drained-stdout"
        assert stderr == b"drained-stderr"
        assert exit_codes == [7]


def test_list_scoped_and_for_all_workspaces(
    sandbox_client: SandboxClient,
    workspace_client: WorkspaceClient,
) -> None:
    import contextlib
    import uuid

    suffix = uuid.uuid4().hex[:8]
    other_ws = f"list-ws-{suffix}"
    created_default: list[str] = []
    created_other: list[str] = []

    try:
        workspace_client.create(other_ws)

        ref_default = sandbox_client.create(
            workspace="default", name=f"ls-def-{suffix}"
        )
        created_default.append(ref_default.name)

        ref_other = sandbox_client.create(workspace=other_ws, name=f"ls-oth-{suffix}")
        created_other.append(ref_other.name)

        default_ids = set(sandbox_client.list_ids(workspace="default"))
        assert ref_default.id in default_ids
        assert ref_other.id not in default_ids

        other_ids = set(sandbox_client.list_ids(workspace=other_ws))
        assert ref_other.id in other_ids
        assert ref_default.id not in other_ids

        all_ids = set(sandbox_client.list_ids_for_all_workspaces())
        assert ref_default.id in all_ids
        assert ref_other.id in all_ids
    finally:
        for name in created_default:
            with contextlib.suppress(Exception):
                sandbox_client.delete(name, workspace="default")
                sandbox_client.wait_deleted(name, workspace="default")
        for name in created_other:
            with contextlib.suppress(Exception):
                sandbox_client.delete(name, workspace=other_ws)
                sandbox_client.wait_deleted(name, workspace=other_ws)
        with contextlib.suppress(Exception):
            workspace_client.delete(other_ws)


def test_sandbox_labels_and_selectors(sandbox_client: SandboxClient) -> None:
    import contextlib
    import uuid

    suffix = uuid.uuid4().hex[:8]
    job_a = f"lbl-a-{suffix}"
    job_b = f"lbl-b-{suffix}"
    group_selector = f"aiq-test={suffix}"
    primary_selector = f"aiq-test={suffix},role=primary"

    created: list[str] = []
    try:
        ref_a = sandbox_client.create(
            workspace="default",
            name=job_a,
            labels={"aiq-test": suffix, "role": "primary"},
        )
        created.append(ref_a.name)
        ref_b = sandbox_client.create(
            workspace="default",
            name=job_b,
            labels={"aiq-test": suffix, "role": "secondary"},
        )
        created.append(ref_b.name)

        # Labels round-trip through create and get.
        assert ref_a.labels["role"] == "primary"
        assert (
            dict(sandbox_client.get(job_a, workspace="default").labels)["role"]
            == "primary"
        )
        assert (
            dict(sandbox_client.get(job_b, workspace="default").labels)["role"]
            == "secondary"
        )

        # A specific selector filters to exactly the primary sandbox.
        assert {
            s.name
            for s in sandbox_client.list_all(
                workspace="default", label_selector=primary_selector
            )
        } == {job_a}
        # The shared group label returns both.
        assert {
            s.name
            for s in sandbox_client.list_all(
                workspace="default", label_selector=group_selector
            )
        } == {
            job_a,
            job_b,
        }

        # Deleting one removes only it from selector results.
        assert sandbox_client.delete(job_a, workspace="default")
        sandbox_client.wait_deleted(job_a, workspace="default")
        created.remove(job_a)
        assert {
            s.name
            for s in sandbox_client.list_all(
                workspace="default", label_selector=group_selector
            )
        } == {job_b}

        # Final deletion leaves no matching sandboxes.
        assert sandbox_client.delete(job_b, workspace="default")
        sandbox_client.wait_deleted(job_b, workspace="default")
        created.remove(job_b)
        assert not sandbox_client.list_all(
            workspace="default", label_selector=group_selector
        )
    finally:
        for name in created:
            with contextlib.suppress(Exception):
                sandbox_client.delete(name, workspace="default")
