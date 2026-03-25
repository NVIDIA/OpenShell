#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
TCP proxy that waits for the k3s apiserver to be ready on 127.0.0.1:6444,
then accepts connections on 0.0.0.0:6443 and forwards them to the apiserver.

This decouples the TSI-exposed port from k3s's internal dynamiclistener,
which has TLS handshake issues when accessed through TSI.
"""

import os
import socket
import sys
import threading
import time

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("PROXY_LISTEN_PORT", "6443"))
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = int(os.environ.get("PROXY_UPSTREAM_PORT", "6444"))
BUFFER_SIZE = 65536


def wait_for_upstream():
    """Block until the upstream apiserver completes a TLS handshake.

    A raw TCP connect succeeds as soon as the port is bound, but the TLS
    server may not be ready yet. We do a full TLS handshake to confirm.
    """
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    attempt = 0
    while True:
        attempt += 1
        try:
            sock = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=5)
            ssock = ctx.wrap_socket(sock, server_hostname="localhost")
            ssock.close()
            print(f"[proxy] upstream TLS ready after {attempt} attempts", flush=True)
            return
        except (
            ConnectionRefusedError,
            ConnectionResetError,
            OSError,
            ssl.SSLError,
        ) as e:
            if attempt % 5 == 0:
                print(
                    f"[proxy] waiting for upstream (attempt {attempt}): {e}", flush=True
                )
        time.sleep(1)


def forward(src, dst, label):
    """Forward data between two sockets until one closes."""
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(client_sock, client_addr):
    """Connect to upstream and forward bidirectionally."""
    print(f"[proxy] accepted connection from {client_addr}", flush=True)
    try:
        upstream = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=5)
        print(f"[proxy] connected to upstream for {client_addr}", flush=True)
    except OSError as e:
        print(
            f"[proxy] failed to connect to upstream for {client_addr}: {e}", flush=True
        )
        client_sock.close()
        return

    # Forward in both directions
    t1 = threading.Thread(
        target=forward, args=(client_sock, upstream, "client->upstream"), daemon=True
    )
    t2 = threading.Thread(
        target=forward, args=(upstream, client_sock, "upstream->client"), daemon=True
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    print(f"[proxy] connection closed for {client_addr}", flush=True)
    client_sock.close()
    upstream.close()


def main():
    # Wait for the real apiserver to be ready before accepting connections
    print(
        f"[proxy] waiting for upstream at {UPSTREAM_HOST}:{UPSTREAM_PORT}...",
        flush=True,
    )
    wait_for_upstream()

    # Start listening
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(64)
    print(
        f"[proxy] listening on {LISTEN_HOST}:{LISTEN_PORT} -> {UPSTREAM_HOST}:{UPSTREAM_PORT}",
        flush=True,
    )

    while True:
        client_sock, client_addr = server.accept()
        threading.Thread(
            target=handle_client, args=(client_sock, client_addr), daemon=True
        ).start()


if __name__ == "__main__":
    main()
