# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# A TCP server on 127.0.0.1:argv[1] that answers each connection's first
# read with b"echo:" and the bytes read, then closes it.

import socket
import sys

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", int(sys.argv[1])))
server.listen(8)
while True:
    conn, _ = server.accept()
    with conn:
        data = conn.recv(4096)
        if data:
            conn.sendall(b"echo:" + data)
