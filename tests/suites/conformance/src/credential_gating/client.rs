// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Commands the tests run in the sandbox.

use super::{TEST_HOST, TOKEN_ENV};

/// Prints `TOKEN_ABSENT`, `TOKEN_PLACEHOLDER`, or `TOKEN_UNSAFE` for the
/// provider's environment variable, without printing its value.
pub(super) const KEY_PRESENCE_SCRIPT: &str = r#"if [ "${E2E_GATING_TOKEN+x}" != x ]; then
  echo TOKEN_ABSENT
else
  case "$E2E_GATING_TOKEN" in
    openshell:resolve:env:*) echo TOKEN_PLACEHOLDER ;;
    *) echo TOKEN_UNSAFE ;;
  esac
fi"#;

/// POSTs a body containing the provider's token to the HTTP probe and prints
/// the probe's verdict, or `BODY_DENIED` without one.
pub(super) fn body_client_script(port: u16) -> String {
    format!(
        r#"
import os
import socket

host = {TEST_HOST:?}
port = {port}
token = os.environ[{TOKEN_ENV:?}]

with socket.create_connection((host, port), timeout=10) as sock:
    target = f"{{host}}:{{port}}"
    body = ("prefix-" + token + "-suffix").encode("utf-8")
    request = (
        f"POST /token HTTP/1.1\r\nHost: {{target}}\r\n"
        f"Content-Type: text/plain\r\nContent-Length: {{len(body)}}\r\nConnection: close\r\n\r\n"
    ).encode("ascii") + body
    sock.sendall(request)
    sock.settimeout(3)
    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        response += chunk
    print("BODY_REWRITTEN" if b"BODY_REWRITTEN" in response else "BODY_TEXT" if b"BODY_TEXT" in response else "BODY_DENIED")
"#
    )
}

/// Upgrades to WebSocket at the probe, sends one binary frame, and prints
/// `BINARY_DENIED` if the connection closed or answered with close code 1008,
/// or `BINARY_FORWARDED` otherwise.
pub(super) fn binary_websocket_client_script(port: u16) -> String {
    format!(
        r#"
import base64
import os
import socket
import struct

host = {TEST_HOST:?}
port = {port}

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data

with socket.create_connection((host, port), timeout=10) as sock:
    target = f"{{host}}:{{port}}"
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET /ws HTTP/1.1\r\nHost: {{target}}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {{key}}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode("ascii"))
    if not recv_until(sock, b"\r\n\r\n").startswith(b"HTTP/1.1 101"):
        raise RuntimeError("upgrade failed")
    payload = b"binary-credential-channel"
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    frame = bytes([0x82, 0x80 | len(payload)]) + mask + masked
    sock.sendall(frame)
    sock.settimeout(3)
    denied = False
    try:
        header = recv_exact(sock, 2)
        if not header:
            denied = True
        elif len(header) == 2:
            opcode = header[0] & 0x0f
            masked = bool(header[1] & 0x80)
            payload_length = header[1] & 0x7f
            if opcode == 0x08 and not masked and payload_length < 126:
                close_payload = recv_exact(sock, payload_length)
                denied = (
                    len(close_payload) >= 2
                    and struct.unpack("!H", close_payload[:2])[0] == 1008
                )
    except socket.timeout:
        denied = True
    print("BINARY_DENIED" if denied else "BINARY_FORWARDED")
"#
    )
}
