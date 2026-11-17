# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Asks to upgrade a REST endpoint to WebSocket with an origin-form and an
# absolute-form target, and fails unless the sandbox refuses both.
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])

for target in ["/allowed", f"http://{HOST}:{PORT}/allowed"]:
    s = socket.create_connection((HOST, PORT), timeout=15)
    request = ("GET " + target + f" HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
               "Connection: Upgrade\r\nUpgrade: websocket\r\n"
               "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    s.sendall(request.encode())
    response = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        response += chunk
    s.close()
    assert response.startswith(b"HTTP/1.1 403"), response
    assert b"unsupported_l7_protocol" in response, response
    assert b"REST endpoints" in response, response
print("REST_UPGRADE_REFUSED")
