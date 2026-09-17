# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        bodies = {
            "/clean": b"ordinary public text",
            "/sensitive": b"contains prototype-secret and internal-only",
        }
        body = bodies.get(self.path, b"not found")
        self.send_response(200 if self.path in bodies else 404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


with ThreadingHTTPServer(("0.0.0.0", 18081), Handler) as server:
    print("content guard upstream listening on 0.0.0.0:18081", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
