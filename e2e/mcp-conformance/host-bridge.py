#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Host bridge for the MCP conformance runner.

The conformance runner runs in an isolated container and posts the URL of its
MCP test server to this bridge. The bridge runs the real MCP client inside an
OpenShell sandbox (via client-through-openshell.sh) and returns its result, so
the untrusted runner never needs gateway credentials.

Usage: host-bridge.py <port> <repo-root> <log-path>
"""

import hmac
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PORT = int(sys.argv[1])
ROOT = Path(sys.argv[2])
LOG_PATH = Path(sys.argv[3])
TIMEOUT = (
    int(os.environ.get("OPENSHELL_MCP_CONFORMANCE_CLIENT_TIMEOUT_SECONDS", "120")) + 30
)
REQUEST_BODY_TIMEOUT_SECONDS = 10
MAX_REQUEST_BODY_BYTES = 256 * 1024
TOKEN_HEADER = "x-openshell-mcp-conformance-token"
BRIDGE_TOKEN = os.environ["OPENSHELL_MCP_CONFORMANCE_BRIDGE_TOKEN"]
RUNNER_IP = os.environ["OPENSHELL_MCP_CONFORMANCE_RUNNER_IP"]
ALLOWED_CONFORMANCE_ENV = frozenset(
    {
        "MCP_CONFORMANCE_SCENARIO",
        "MCP_CONFORMANCE_CONTEXT",
        "MCP_CONFORMANCE_PROTOCOL_VERSION",
    }
)
HOST_ENV_ALLOWLIST = frozenset(
    {
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "HOME",
        "LANG",
        "LC_ALL",
        "MISE_CACHE_DIR",
        "MISE_CONFIG_DIR",
        "MISE_DATA_DIR",
        "MISE_STATE_DIR",
        "OPENSHELL_BIN",
        "OPENSHELL_GATEWAY",
        "OPENSHELL_MCP_CONFORMANCE_CLIENT_SANDBOX",
        "OPENSHELL_MCP_CONFORMANCE_CLIENT_TIMEOUT_SECONDS",
        "OPENSHELL_MCP_CONFORMANCE_POLICY_WAIT",
        "OPENSHELL_MCP_CONFORMANCE_POLICY_WAIT_TIMEOUT",
        "OPENSHELL_PROVISION_TIMEOUT",
        "PATH",
        "RUSTUP_HOME",
        "TMP",
        "TEMP",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
    }
)


def log(message: str) -> None:
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(message + "\n")


def canonical_ip(value: str):
    parsed = ip_address(value)
    return getattr(parsed, "ipv4_mapped", None) or parsed


def captured_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def subprocess_env(
    payload_env: dict[str, str], expected_server_host: str
) -> dict[str, str]:
    env = {name: os.environ[name] for name in HOST_ENV_ALLOWLIST if name in os.environ}
    env.update(payload_env)
    env["OPENSHELL_MCP_CONFORMANCE_EXPECTED_SERVER_HOST"] = expected_server_host
    return env


class Handler(BaseHTTPRequestHandler):
    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(REQUEST_BODY_TIMEOUT_SECONDS)

    def send_json(self, status: int, body: dict[str, object]) -> None:
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(encoded)

    def reject(self, status: int, detail: str) -> None:
        self.close_connection = True
        log(f"rejecting bridge request from {self.client_address[0]}: {detail}")
        self.send_json(status, {"error": "invalid_bridge_request", "detail": detail})

    def bridge_token_valid(self) -> bool:
        supplied = self.headers.get(TOKEN_HEADER, "")
        return hmac.compare_digest(supplied, BRIDGE_TOKEN)

    def request_body_length(self) -> int | None:
        raw_length = self.headers.get("content-length")
        if raw_length is None:
            self.reject(411, "content-length is required")
            return None
        try:
            length = int(raw_length)
        except ValueError:
            self.reject(400, "content-length must be an integer")
            return None
        if length < 0:
            self.reject(400, "content-length must not be negative")
            return None
        if length > MAX_REQUEST_BODY_BYTES:
            self.reject(413, "request body is too large")
            return None
        return length

    def read_request_payload(self, length: int) -> dict[str, Any] | None:
        try:
            raw_body = self.rfile.read(length)
        except TimeoutError:
            self.reject(408, "timed out reading request body")
            return None
        if len(raw_body) != length:
            self.reject(400, "request body ended before content-length")
            return None
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError as err:
            self.reject(400, str(err))
            return None
        if not isinstance(payload, dict):
            self.reject(400, "request body must be a JSON object")
            return None
        return payload

    def do_POST(self) -> None:
        if self.path != "/run":
            self.send_response(404)
            self.end_headers()
            return

        if not self.bridge_token_valid():
            self.reject(403, "invalid bridge capability")
            return

        length = self.request_body_length()
        if length is None:
            return

        payload = self.read_request_payload(length)
        if payload is None:
            return

        server_url = payload.get("server_url")
        if not isinstance(server_url, str):
            self.reject(400, "server_url must be a string")
            return

        parsed = urlparse(server_url)
        if parsed.scheme not in {"http", "https"}:
            self.reject(403, "server_url scheme must be http or https")
            return

        try:
            target_ip = canonical_ip(parsed.hostname or "")
            expected_ip = canonical_ip(RUNNER_IP)
        except ValueError:
            self.reject(403, "server_url host must match the runner container IP")
            return

        if target_ip != expected_ip:
            self.reject(403, "server_url host must match the runner container IP")
            return

        payload_env = payload.get("env", {})
        if not isinstance(payload_env, dict):
            self.reject(400, "env must be an object")
            return
        if any(name not in ALLOWED_CONFORMANCE_ENV for name in payload_env):
            self.reject(403, "env contains unsupported keys")
            return
        if any(not isinstance(value, str) for value in payload_env.values()):
            self.reject(400, "env values must be strings")
            return

        env = subprocess_env(payload_env, str(expected_ip))
        log(f"running client for {server_url}")
        try:
            result = subprocess.run(
                ["bash", "e2e/mcp-conformance/client-through-openshell.sh", server_url],
                cwd=ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
            )
            log(f"client exited {result.returncode} for {server_url}")
            body = {
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired as err:
            body = {
                "exit_code": 124,
                "stdout": captured_text(err.stdout),
                "stderr": captured_text(err.stderr)
                + f"\nhost bridge timed out after {TIMEOUT}s\n",
            }
        self.send_json(200, body)

    def log_message(self, format: str, *args: Any) -> None:
        log(format % args)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log(f"host bridge listening on {PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
