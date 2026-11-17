# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends the bytes hex-encoded in argv[3] to the echo server at
# argv[1]:argv[2] and fails unless it reads the same bytes back.
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])
PAYLOAD = bytes.fromhex(sys.argv[3])

with socket.create_connection((HOST, PORT), timeout=10) as sock:
    sock.sendall(PAYLOAD)
    echoed = b""
    while len(echoed) < len(PAYLOAD):
        chunk = sock.recv(len(PAYLOAD) - len(echoed))
        if not chunk:
            break
        echoed += chunk
if echoed != PAYLOAD:
    raise SystemExit(f"the payload changed in transit: {echoed!r}")
print("ECHO_OK")
