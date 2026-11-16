# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Loopback HTTP/WebSocket fixture; identity and counter survive supervisor moves."""

import base64
import hashlib
import json
import os
import struct
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BOOT = str(uuid.uuid4())


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counter = 0

    def do_GET(self):
        Handler.counter += 1
        if self.headers.get("Upgrade", "").lower() != "websocket":
            body = json.dumps(
                {
                    "headers": dict(self.headers),
                    "boot": BOOT,
                    "pid": os.getpid(),
                    "counter": Handler.counter,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # SHA-1 is mandated by the WebSocket handshake, not used for authentication.
        accept = base64.b64encode(
            hashlib.sha1(
                (
                    self.headers["Sec-WebSocket-Key"]
                    + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                ).encode(),
                usedforsecurity=False,
            ).digest()
        ).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        while True:
            head = self.rfile.read(2)
            if len(head) != 2 or head[0] & 15 == 8:
                return
            length = head[1] & 127
            if length == 126:
                length = struct.unpack("!H", self.rfile.read(2))[0]
            if length > 125 or not head[1] & 128:
                return  # Fixture deliberately accepts only small masked frames.
            mask = self.rfile.read(4)
            data = self.rfile.read(length)
            if len(mask) != 4 or len(data) != length:
                return
            data = bytes(value ^ mask[i % 4] for i, value in enumerate(data))
            self.wfile.write(bytes([0x81, len(data)]) + data)
            self.wfile.flush()


ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
