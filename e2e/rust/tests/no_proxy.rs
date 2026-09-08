// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use openshell_e2e::harness::sandbox::SandboxGuard;

fn localhost_transparent_script() -> &'static str {
    r#"
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
"#
}

#[tokio::test]
async fn sandbox_reaches_localhost_without_proxy_environment() {
    let guard = SandboxGuard::create(&["--", "python3", "-c", localhost_transparent_script()])
        .await
        .expect("sandbox create with transparent localhost check");

    assert!(
        guard
            .create_output
            .contains(r#"{"proxy_env_absent": true, "payload": {"message": "hello"}}"#),
        "expected localhost HTTP request to stay local and succeed:\n{}",
        guard.create_output
    );
}
