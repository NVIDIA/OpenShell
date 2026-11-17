# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Serves HTTP on 127.0.0.1 and fetches from it, with no proxy variables in
# the environment.
import json
import os
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy'):
    assert name not in os.environ, f'unexpected proxy environment variable: {name}'

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"message":"hello"}')

server = HTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()

try:
    with urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}', timeout=10) as response:
        print(json.dumps({
            'proxy_env_absent': True,
            'payload': json.loads(response.read().decode()),
        }), flush=True)
finally:
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()
