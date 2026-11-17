# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends bytes that are neither HTTP nor TLS to argv[1]:argv[2] and fails if
# the connection answers with anything but a 403 unsupported_l7_protocol
# denial. A reset or an empty close also counts as blocked.
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])
PAYLOAD = bytes([0x00, 0xFF, 0x13, 0x37]) + b"not-http-or-tls"

with socket.create_connection((HOST, PORT), timeout=10) as sock:
    sock.sendall(PAYLOAD)
    denial = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except ConnectionResetError:
            break
        if not chunk:
            break
        denial += chunk
if denial and (
    b"HTTP/1.1 403 Forbidden" not in denial
    or b"unsupported_l7_protocol" not in denial
):
    raise SystemExit(f"missing the middleware denial: {denial!r}")
print("BLOCKED")
