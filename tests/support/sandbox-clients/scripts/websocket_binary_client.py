# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Upgrades to WebSocket at argv[1]:argv[2]/ws, sends one binary frame, and
# waits up to three seconds for a reply or the connection to close.

import base64
import os
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])

with socket.create_connection((HOST, PORT), timeout=10) as sock:
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(
        f"GET /ws HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n".encode()
    )
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            sys.exit(f"closed during the upgrade: {response!r}")
        response += chunk
    if not response.startswith(b"HTTP/1.1 101"):
        sys.exit(f"upgrade failed: {response!r}")
    payload, mask = b"binary-credential-channel", os.urandom(4)
    sock.sendall(
        bytes([0x82, 0x80 | len(payload)])
        + mask
        + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    )
    sock.settimeout(3)
    try:
        sock.recv(4096)
    except (TimeoutError, ConnectionError):
        pass
