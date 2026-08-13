"""Minimal Redis client for the transparent TCP example."""

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ipaddress
import socket
import sys

HOST = "redis.openshell.demo"
PORT = 6379
KEY = "openshell:transparent-tcp-demo"


def encode_command(*parts: str) -> bytes:
    encoded = [part.encode() for part in parts]
    request = [f"*{len(encoded)}\r\n".encode()]
    for part in encoded:
        request.extend((f"${len(part)}\r\n".encode(), part, b"\r\n"))
    return b"".join(request)


def read_response(stream):
    marker = stream.read(1)
    if not marker:
        raise RuntimeError("Redis closed the connection")
    line = stream.readline().removesuffix(b"\r\n")
    if marker == b"+":
        return line.decode()
    if marker == b":":
        return int(line)
    if marker == b"$":
        length = int(line)
        if length == -1:
            return None
        value = stream.read(length)
        if stream.read(2) != b"\r\n":
            raise RuntimeError("invalid Redis bulk response")
        return value.decode()
    if marker == b"-":
        raise RuntimeError(f"Redis error: {line.decode()}")
    raise RuntimeError(f"unsupported Redis response marker: {marker!r}")


def command(connection: socket.socket, stream, *parts: str):
    connection.sendall(encode_command(*parts))
    result = read_response(stream)
    print(f"{parts[0]} -> {result!r}")
    return result


def expect_connection_blocked(label: str, host: str, port: int) -> None:
    try:
        with (
            socket.create_connection((host, port), timeout=3) as connection,
            connection.makefile("rb") as stream,
        ):
            connection.sendall(encode_command("PING"))
            response = read_response(stream)
    except (OSError, RuntimeError) as error:
        print(f"BLOCKED ({label}): {host}:{port} -> {type(error).__name__}")
        return
    raise RuntimeError(
        f"{label} unexpectedly reached Redis at {host}:{port}: {response!r}"
    )


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: redis_client.py REDIS_REAL_IP UNAPPROVED_HOSTNAME")
    redis_real_ip, unapproved_hostname = sys.argv[1:]

    addresses = sorted(
        {item[4][0] for item in socket.getaddrinfo(HOST, PORT, type=socket.SOCK_STREAM)}
    )
    print(f"policy DNS: {HOST} -> {', '.join(addresses)}")
    if not any(
        ipaddress.ip_address(address) in ipaddress.ip_network("198.18.0.0/15")
        for address in addresses
        if ipaddress.ip_address(address).version == 4
    ):
        raise RuntimeError("policy DNS did not return an IPv4 synthetic address")

    with (
        socket.create_connection((HOST, PORT), timeout=10) as connection,
        connection.makefile("rb") as stream,
    ):
        assert command(connection, stream, "PING") == "PONG"
        assert command(connection, stream, "SET", KEY, "hello-from-openshell") == "OK"
        assert command(connection, stream, "GET", KEY) == "hello-from-openshell"
        assert command(connection, stream, "DEL", KEY) == 1

    print("\nChecking connections that policy must block...")
    expect_connection_blocked("unapproved hostname", unapproved_hostname, PORT)
    expect_connection_blocked("wrong port", HOST, PORT + 1)
    expect_connection_blocked("direct real-IP dial", redis_real_ip, PORT)

    print("transparent TCP Redis demo passed")


if __name__ == "__main__":
    main()
