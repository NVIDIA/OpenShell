# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs in a fixture container (src/echo.rs). Listens on each port in argv,
# and answers each connection's first read with the same bytes, after
# printing them to stdout so a test can see what arrived.
import socket
import sys
import threading


def serve(port):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen()
    while True:
        conn, _ = listener.accept()
        with conn:
            data = conn.recv(1024)
            if data:
                print(data.decode("ascii", "replace"), flush=True)
                conn.sendall(data)


ports = [int(port) for port in sys.argv[1:]]
for port in ports[1:]:
    threading.Thread(target=serve, args=(port,), daemon=True).start()
serve(ports[0])
