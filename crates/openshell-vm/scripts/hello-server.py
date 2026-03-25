#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Minimal HTTP server that responds with 'Hello from libkrun VM!' on port 8080."""

import json
import os
import platform
from http.server import HTTPServer, BaseHTTPRequestHandler


class HelloHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(
            {
                "message": "Hello from libkrun VM!",
                "hostname": platform.node(),
                "platform": platform.platform(),
                "arch": platform.machine(),
                "pid": os.getpid(),
                "path": self.path,
            },
            indent=2,
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        print(f"[hello-server] {args[0]}")


def main():
    host = "0.0.0.0"
    port = 8080
    server = HTTPServer((host, port), HelloHandler)
    print(f"Hello server listening on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
