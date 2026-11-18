# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Upgrades to WebSocket at argv[1]:argv[2], sends the provider's token from
# E2E_GATING_TOKEN in one text frame, and prints the server's text reply.
# Never prints the token.
import base64
import json
import os
import socket
import struct
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])
TOKEN = os.environ["E2E_GATING_TOKEN"]


def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("the connection closed mid-frame")
        data += chunk
    return data


def masked_text_frame(text):
    data = text.encode()
    mask = os.urandom(4)
    if len(data) < 126:
        header = bytes([0x81, 0x80 | len(data)])
    else:
        header = bytes([0x81, 0x80 | 126]) + struct.pack("!H", len(data))
    return header + mask + bytes(byte ^ mask[i % 4] for i, byte in enumerate(data))


def read_text_frame(sock):
    _, second = read_exact(sock, 2)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(sock, 8))[0]
    mask = read_exact(sock, 4) if second & 0x80 else b""
    payload = read_exact(sock, length)
    if mask:
        payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload))
    return payload.decode()


with socket.create_connection((HOST, PORT), timeout=10) as sock:
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(
        (
            "GET /ws HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
    )
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    if not response.startswith(b"HTTP/1.1 101"):
        raise SystemExit(f"upgrade failed: {response!r}")
    sock.sendall(masked_text_frame(json.dumps({"authorization": "Bearer " + TOKEN})))
    print(read_text_frame(sock))
