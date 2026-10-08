# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Joined protocol-v3 acceptance through the real supervisor bootstrap."""

import json
import os
import socket
from pathlib import Path

root = Path("/sandbox/assistant")
root.mkdir(mode=0o700)
for folder in (
    "workspace",
    "agent",
    "skills",
    "memory",
    "runtime",
    "run",
    "run/turns",
    "run/scratch",
    "run/scratch/turn",
):
    (root / folder).mkdir(mode=0o700)
(root / "runtime/data.db").write_text("private database")
(root / "skills/test.md").write_text("read-only skill")
turn_socket = root / "run/turns/turn.sock"
listener = socket.socket(socket.AF_UNIX)
listener.bind(str(turn_socket))
os.chmod(turn_socket, 0o600)
listener.listen()


def run(command, timeout=30):
    request = {
        "protocol_version": 3,
        "command": command,
        "agent_root": str(root),
        "turn_socket": str(turn_socket),
        "cwd": "agent",
        "timeout_seconds": timeout,
    }
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(timeout + 10)
        connection.connect("/tmp/openshell-bwrap-launcher.sock")
        connection.sendall(json.dumps(request).encode() + b"\n")
        response = b""
        while not response.endswith(b"\n"):
            chunk = connection.recv(65536)
            if not chunk:
                raise RuntimeError("launcher disconnected")
            response += chunk
        return json.loads(response)


result = run(
    'sleep 6; git --version; python --version; node --version; python -c "import asyncio; asyncio.run(asyncio.sleep(0))"; echo computer-ready'
)
assert result["exit_code"] == 0 and "computer-ready" in result["stdout"], result
assert result["duration_ms"] >= 6000 and not result["timed_out"], result
result = run(
    "test ! -e /sandbox && test ! -e /workspace && test ! -e /app && test ! -e /runtime/data.db; echo boundary:$?; cat /skills/test.md; (echo edit >> /skills/test.md)"
)
assert (
    "boundary:0" in result["stdout"]
    and "read-only skill" in result["stdout"]
    and result["exit_code"] != 0
), result
result = run('python -c "import socket; socket.socket(socket.AF_INET)"')
assert result["exit_code"] != 0 and "Operation not permitted" in result["stderr"], (
    result
)
result = run("python -c \"print('x' * 2000000)\"")
assert len(result["stdout"]) == 1048576 and result["stdout_truncated"], result
result = run("sleep 20 & wait", timeout=1)
assert result["timed_out"] and result["duration_ms"] < 5000, result
print(json.dumps({"computer_jail": "passed", "uid": os.getuid()}))
