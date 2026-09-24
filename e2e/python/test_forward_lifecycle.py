# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import pytest

from openshell._proto import openshell_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from openshell import Sandbox, SandboxClient


@pytest.mark.parametrize("response_first", [False, True])
def test_forward_preserves_bytes_after_opposite_fin(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
    response_first: bool,
) -> None:
    """Exercise real TCP FIN through ForwardTcp and the built supervisor."""
    port_file = f"/sandbox/forward-{uuid.uuid4().hex}.port"
    server = f"""
import socket
from pathlib import Path
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(30)
    Path({port_file!r}).write_text(str(listener.getsockname()[1]))
    with listener.accept()[0] as connection:
        connection.settimeout(30)
        if {response_first!r}:
            connection.sendall(b'response')
            connection.shutdown(socket.SHUT_WR)
        request = bytearray()
        while chunk := connection.recv(4096):
            request.extend(chunk)
        assert request == b'request after FIN'
        if not {response_first!r}:
            connection.sendall(b'response')
            connection.shutdown(socket.SHUT_WR)
"""
    wait_ready = f"""
import time
from pathlib import Path
path = Path({port_file!r})
deadline = time.monotonic() + 20
while not path.exists() and time.monotonic() < deadline:
    time.sleep(0.05)
print(path.read_text())
"""
    with sandbox(delete_on_exit=True) as sb, ThreadPoolExecutor(max_workers=1) as pool:
        target = pool.submit(sb.exec, ["python", "-c", server], timeout_seconds=45)
        ready = sb.exec(["python", "-c", wait_ready], timeout_seconds=25)
        assert ready.exit_code == 0, ready.stderr
        port = int(ready.stdout.strip())
        response_fin = threading.Event()

        def requests():
            yield openshell_pb2.TcpForwardFrame(
                init=openshell_pb2.TcpForwardInit(
                    sandbox=sb.sandbox.name,
                    workspace="default",
                    tcp=openshell_pb2.TcpRelayTarget(host="127.0.0.1", port=port),
                    capabilities=["stream-half-close-v1"],
                )
            )
            if response_first:
                assert response_fin.wait(30), "response FIN did not arrive"
            yield openshell_pb2.TcpForwardFrame(data=b"request after FIN")

        output = bytearray()
        fin_count = 0
        try:
            for frame in sandbox_client._stub.ForwardTcp(requests(), timeout=35):
                kind = frame.WhichOneof("payload")
                if kind == "half_close":
                    fin_count += 1
                    response_fin.set()
                else:
                    assert kind == "data" and fin_count == 0
                    output.extend(frame.data)
        finally:
            response_fin.set()
        assert output == b"response"
        assert fin_count == 1
        result = target.result(timeout=10)
        assert result.exit_code == 0, result.stderr
