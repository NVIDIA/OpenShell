# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sends the pipelined HTTP requests in argv[3] to argv[1]:argv[2] in one
# write, reads until the connection closes, and prints the status lines of
# the responses.
import json
import socket
import sys

HOST = sys.argv[1]
PORT = int(sys.argv[2])
REQUESTS = sys.argv[3].encode()

with socket.create_connection((HOST, PORT), timeout=10) as sock:
    sock.sendall(REQUESTS)
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
statuses = [
    line.decode(errors="replace")
    for line in response.split(b"\r\n")
    if line.startswith(b"HTTP/1.1 ")
]
print(json.dumps({"statuses": statuses}))
