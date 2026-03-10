# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Minimal REST API for the bring-your-own-container example.

Run with:
    python app.py

Endpoints:
    GET /hello         -> {"message": "hello from OpenShell sandbox!"}
    GET /hello/<name>  -> {"message": "hello, <name>!"}
    GET /health        -> {"status": "ok"}
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

PORT = 8080


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok"})
        elif self.path == "/hello":
            self._json(200, {"message": "hello from OpenShell sandbox!"})
        elif self.path.startswith("/hello/"):
            name = self.path[len("/hello/") :]
            self._json(200, {"message": f"hello, {name}!"})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # Suppress per-request log lines for cleaner output.
    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"listening on 0.0.0.0:{PORT}")
    server.serve_forever()
