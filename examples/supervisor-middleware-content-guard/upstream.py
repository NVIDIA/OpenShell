# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


BODIES = {
    "/clean": b"ordinary public text",
    "/sensitive": b"contains prototype-secret and internal-only",
}


class Handler(BaseHTTPRequestHandler):
    def respond(self, send_body):
        body = BODIES.get(self.path, b"not found")
        self.send_response(200 if self.path in BODIES else 404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def do_GET(self):
        self.respond(send_body=True)

    def do_HEAD(self):
        self.respond(send_body=False)


with ThreadingHTTPServer(("0.0.0.0", 18081), Handler) as server:
    print("content guard upstream listening on 0.0.0.0:18081", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
