// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use openshell_e2e::harness::sandbox::SandboxGuard;

fn localhost_bypass_script() -> &'static str {
    r#"
import json
import os
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

expected_no_proxy = '127.0.0.1,localhost,::1'
assert os.environ['HTTP_PROXY'].startswith('http://')
assert os.environ['HTTPS_PROXY'].startswith('http://')
assert os.environ['NO_PROXY'] == expected_no_proxy
assert os.environ['no_proxy'] == expected_no_proxy

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
            'no_proxy': os.environ['NO_PROXY'],
            'payload': json.loads(response.read().decode()),
        }), flush=True)
finally:
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()
"#
}

#[tokio::test]
async fn sandbox_bypasses_proxy_for_localhost_http() {
    let guard = SandboxGuard::create(&["--", "python3", "-c", localhost_bypass_script()])
        .await
        .expect("sandbox create with localhost proxy bypass check");

    assert!(
        guard.create_output.contains(
            r#"{"no_proxy": "127.0.0.1,localhost,::1", "payload": {"message": "hello"}}"#
        ),
        "expected localhost HTTP request to bypass proxy and succeed:\n{}",
        guard.create_output
    );
}
