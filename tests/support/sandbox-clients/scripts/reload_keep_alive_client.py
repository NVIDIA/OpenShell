# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends a keep-alive GET to argv[1]:argv[2] and prints `ready` once it
# succeeds, or the error. After a line arrives on stdin, sends a second request
# on the same connection and prints its status as JSON, 0 if it was refused.
import json
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])


def read_response(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return 0
        data += chunk
    headers, body = data.split(b"\r\n\r\n", 1)
    length = 0
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            return 0
        body += chunk
    return int(headers.split(None, 2)[1])


target = f"{HOST}:{PORT}"
with socket.create_connection((HOST, PORT), timeout=10) as sock:
    try:
        sock.sendall(
            f"GET /before-reload HTTP/1.1\r\nHost: {target}\r\nConnection: keep-alive\r\n\r\n".encode()
        )
        first_status = read_response(sock)
    except OSError as error:
        first_status = repr(error)
    print("ready" if first_status == 200 else f"first request failed: {first_status}", flush=True)
    sys.stdin.readline()
    try:
        sock.sendall(
            f"GET /after-reload HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode()
        )
        second_status = read_response(sock)
    except OSError:
        second_status = 0
    print(json.dumps({"second_status": second_status}), flush=True)
