# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import socketserver


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        request = b""
        while b"\r\n\r\n" not in request:
            block = self.request.recv(4096)
            if not block:
                return
            request += block
        path = request.split(b" ", 2)[1]
        if path == b"/headers-only":
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
