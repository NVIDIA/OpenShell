#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# PKI vsock server.
#
# Listens on AF_VSOCK port 10778. On each connection, reads the six PEM files
# from PKI_DIR, serialises them as a single JSON object, writes it followed by
# a newline, then closes the connection.  The host-side bootstrap reads the
# object over the libkrun vsock-to-Unix bridge instead of polling the
# virtio-fs rootfs path.
#
# Usage (started by openshell-vm-init.sh after PKI generation):
#   python3 /srv/openshell-vm-pki-server.py /opt/openshell/pki &

import json
import os
import socket
import sys

PORT = 10778

PKI_FILES = ["ca.crt", "ca.key", "server.crt", "server.key", "client.crt", "client.key"]


def serve(pki_dir: str) -> None:
    if not hasattr(socket, "AF_VSOCK"):
        print("AF_VSOCK not available", file=sys.stderr)
        sys.exit(1)

    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((socket.VMADDR_CID_ANY, PORT))
    server.listen(8)

    while True:
        conn, _addr = server.accept()
        try:
            bundle = {}
            for name in PKI_FILES:
                path = os.path.join(pki_dir, name)
                try:
                    with open(path) as f:
                        bundle[name] = f.read()
                except OSError as e:
                    bundle[name] = ""
                    print(f"warning: could not read {path}: {e}", file=sys.stderr)

            payload = (json.dumps(bundle, separators=(",", ":")) + "\n").encode("utf-8")
            conn.sendall(payload)
        except Exception as e:
            print(f"pki-server error: {e}", file=sys.stderr)
        finally:
            conn.close()


if __name__ == "__main__":
    pki_dir = sys.argv[1] if len(sys.argv) > 1 else "/opt/openshell/pki"
    serve(pki_dir)
