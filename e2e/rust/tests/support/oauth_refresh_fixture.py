# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""HTTP OAuth issuer and resource for managed or external gateway tests."""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

current_token = "bootstrap-token"
generation = 0
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        global current_token, generation
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path != "/token":
            self.reply(404)
            return
        with lock:
            generation += 1
            current_token = f"oauth-token-{generation}"
            token = current_token
        self.reply(
            200,
            json.dumps(
                {"access_token": token, "expires_in": 300, "token_type": "Bearer"}
            ).encode(),
        )

    def do_GET(self):
        with lock:
            token = current_token
        basic = "Basic " + base64.b64encode(f"x-access-token:{token}".encode()).decode()
        authorized = self.headers.get("Authorization") in (f"Bearer {token}", basic)
        if self.path == "/" or (self.path == "/probe" and authorized):
            self.reply(204)
        else:
            self.reply(401)

    def log_message(self, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
