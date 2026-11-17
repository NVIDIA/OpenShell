# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends two GET requests to argv[1]:argv[2], each on its own connection, and
# prints their statuses, or the error a connection failed with.
import json
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])


def read_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def status(response):
    parts = response.split(None, 2)
    return int(parts[1]) if len(parts) > 1 else 0


def request_status(path):
    try:
        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            sock.sendall(
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {HOST}:{PORT}\r\nConnection: close\r\n\r\n".encode()
            )
            return status(read_headers(sock))
    except OSError as error:
        return {"errno": error.errno, "error": repr(error)}


print(json.dumps({
    "first": request_status("/first"),
    "second": request_status("/second"),
}, sort_keys=True))
