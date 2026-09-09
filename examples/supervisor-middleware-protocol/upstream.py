# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import hashlib
import socket
import socketserver
import struct


class Handler(socketserver.BaseRequestHandler):
    def read_exact(self, count):
        data = b""
        while len(data) < count:
            block = self.request.recv(count - len(data))
            if not block:
                raise ConnectionError("unexpected EOF")
            data += block
        return data

    def handle(self):
        self.request.settimeout(10)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        request = b""
        while b"\r\n\r\n" not in request:
            block = self.request.recv(4096)
            if not block:
                return
            request += block
        path = request.split(b" ", 2)[1]
        if path == b"/request":
            head, body = request.split(b"\r\n\r\n", 1)
            length = next(int(line.split(b":", 1)[1]) for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:"))
            while len(body) < length:
                block = self.request.recv(length - len(body))
                if not block:
                    return
                body += block
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(length).encode() + b"\r\n\r\n" + body[:length]
        elif path == b"/ws":
            key = next(line.split(b":", 1)[1].strip() for line in request.split(b"\r\n") if line.lower().startswith(b"sec-websocket-key:"))
            accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
            self.request.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
            header = self.read_exact(2)
            length = header[1] & 127
            if length == 126:
                length = struct.unpack("!H", self.read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self.read_exact(8))[0]
            if length > 262144 or header[0] != 0x81 or not header[1] & 0x80:
                return
            mask = self.read_exact(4)
            payload = self.read_exact(length)
            body = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if len(body) < 126:
                framing = bytes([0x81, len(body)])
            elif len(body) < 65536:
                framing = b"\x81\x7e" + struct.pack("!H", len(body))
            else:
                framing = b"\x81\x7f" + struct.pack("!Q", len(body))
            self.request.sendall(framing + body)
            return
        elif path == b"/headers-only":
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 12\r\n\r\n"
                b"headers-only"
            )
        elif path == b"/whole-body":
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"6\r\nwhole \r\n4\r\nbody\r\n0\r\n\r\n"
            )
        elif path == b"/stream":
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Trailer: x-example-body-bytes\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"6\r\nstream\r\n5\r\n body\r\n"
                b"0\r\nX-Example-Body-Bytes: 0\r\n\r\n"
            )
        elif path == b"/stream-close":
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/event-stream\r\n"
                b"Connection: close\r\n\r\n"
                b"data: stream close\n\n"
            )
        elif path == b"/block":
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 16\r\n\r\n"
                b"prototype-secret"
            )
        else:
            response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        self.request.sendall(response)


class DemoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


with DemoServer(("0.0.0.0", 18081), Handler) as server:
    print("response framing demo upstream listening on 0.0.0.0:18081", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
