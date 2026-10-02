# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Minimal loopback accept/getpeername check; run inside an OpenShell sandbox."""

import json
import os
import socket

socket.setdefaulttimeout(10)
with socket.socket() as server, socket.socket() as client:
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client.connect(server.getsockname())
    expected = client.getsockname()
    conn, accepted_peer = server.accept()
    with conn:
        peer = conn.getpeername()
        conn.sendall(b"ping")
        assert client.recv(4) == b"ping"
        assert peer == expected, (peer, expected)
        assert accepted_peer == expected, (accepted_peer, expected)
        assert peer[1] != server.getsockname()[1]
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "client": expected,
                    "accept_peer": accepted_peer,
                    "peer": peer,
                    "preload": os.environ.get("LD_PRELOAD", ""),
                }
            )
        )
