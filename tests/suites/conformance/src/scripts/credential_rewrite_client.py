# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# POSTs the provider's token from E2E_GATING_TOKEN in an Authorization header
# and a JSON body to argv[1]:argv[2]/probe twice, each on its own
# connection, and fails unless both get 200. Never prints the token.
import json
import os
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])
TOKEN = os.environ["E2E_GATING_TOKEN"]


def status(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    parts = data.split(None, 2)
    return int(parts[1]) if len(parts) > 1 else 0


def request_once():
    body = json.dumps({"credential": TOKEN}, separators=(",", ":")).encode()
    request = (
        "POST /probe HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Authorization: Bearer {TOKEN}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        sock.sendall(request)
        return status(sock)


statuses = [request_once(), request_once()]
if statuses != [200, 200]:
    raise SystemExit(f"expected two 200 responses; got {statuses}")
print("REWRITE_OK")
