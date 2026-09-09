# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""One text-message exchange for the protocol smoke test."""

import base64
import hashlib
import os
import socket
from urllib.parse import urlsplit


def read_exact(stream, count):
    data = b""
    while len(data) < count:
        block = stream.recv(count - len(data))
        if not block:
            raise ConnectionError("unexpected EOF")
        data += block
    return data


proxy_url = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
if not proxy_url:
    raise RuntimeError("run this client inside the sandbox with HTTP_PROXY configured")
proxy = urlsplit(proxy_url)
if proxy.scheme != "http" or not proxy.hostname:
    raise RuntimeError("expected an HTTP proxy endpoint")

with socket.create_connection((proxy.hostname, proxy.port or 80), timeout=20) as stream:
    stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    stream.sendall(
        b"CONNECT host.openshell.internal:18081 HTTP/1.1\r\n"
        b"Host: host.openshell.internal:18081\r\n\r\n"
    )
    tunnel = b""
    while not tunnel.endswith(b"\r\n\r\n"):
        tunnel += read_exact(stream, 1)
    assert tunnel.startswith((b"HTTP/1.1 200 ", b"HTTP/1.0 200 ")), tunnel
    key = base64.b64encode(os.urandom(16))
    stream.sendall(
        b"GET /ws HTTP/1.1\r\nHost: host.openshell.internal:18081\r\n"
        b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + b"\r\n\r\n"
    )
    head = b""
    while not head.endswith(b"\r\n\r\n"):
        head += read_exact(stream, 1)
    assert head.startswith(b"HTTP/1.1 101 ")
    expected = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
    assert expected in head
    payload = b"hello protocol"
    mask = os.urandom(4)
    stream.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))
    header = read_exact(stream, 2)
    assert header == bytes([0x81, len(payload)]), header
    print(read_exact(stream, len(payload)).decode())
    stream.sendall(b"\x88\x80" + os.urandom(4))
