# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check outbound relay data transfer independently of peer-address reporting."""

import argparse
import ipaddress
import json
import socket

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("host")
parser.add_argument("port", type=int)
parser.add_argument("--expect-relay", action="store_true")
args = parser.parse_args()
for attempt in range(3):
    with socket.create_connection((args.host, args.port), timeout=10) as conn:
        print(
            json.dumps({"stage": "connect", "attempt": attempt, "result": "PASS"}),
            flush=True,
        )
        try:
            peer = {"result": "PASS", "address": conn.getpeername()}
        except OSError as error:
            peer = {"result": "ERROR", "errno": error.errno, "message": str(error)}
        print(
            json.dumps({"stage": "getpeername", "attempt": attempt, **peer}), flush=True
        )
        if args.expect_relay:
            assert peer["result"] == "PASS", peer
            assert ipaddress.ip_address(peer["address"][0]).is_loopback, peer
            assert peer["address"][1] != 0, peer
        # Exchange bytes after querying the peer, including after a baseline error.
        for size in (4, 262144):
            payload = b"ping" * (size // 4)
            conn.sendall(payload)
            received = bytearray()
            while len(received) < size:
                chunk = conn.recv(min(65536, size - len(received)))
                if not chunk:
                    raise RuntimeError("unexpected EOF from echo server")
                received.extend(chunk)
            assert received == payload
            print(
                json.dumps(
                    {
                        "stage": "echo",
                        "attempt": attempt,
                        "bytes": size,
                        "result": "PASS",
                    }
                ),
                flush=True,
            )
