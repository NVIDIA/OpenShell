# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Executed in a client Pod so probes use actual cluster networking."""

import errno
import http.client
import json
import socket
import ssl
import sys
import time

CONTEXT = ssl.create_default_context(cafile="/test/ca.crt")


def connect(ip, port, hostname, context=CONTEXT):
    raw = socket.create_connection((ip, int(port)), timeout=4)
    try:
        return context.wrap_socket(raw, server_hostname=hostname)
    except BaseException:
        raw.close()
        raise


def request(
    ip,
    port,
    hostname,
    authority=None,
    context=CONTEXT,
    authorization="Bearer application-test-token",
):
    with connect(ip, port, hostname, context) as stream:
        headers = {
            "Host": authority or hostname,
            "Origin": "https://" + hostname,
            "Cookie": "app_session=fixture",
            "X-Openshell-Principal": "must-strip",
            "Connection": "close",
        }
        if authorization is not None:
            headers["Authorization"] = authorization
        stream.sendall(
            (
                "GET / HTTP/1.1\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                + "\r\n"
            ).encode()
        )
        response = http.client.HTTPResponse(stream)
        response.begin()
        body = response.read()
        return response.status, json.loads(
            body
        ) if response.status == 200 else body.decode()


def websocket(ip, port, hostname):
    stream = connect(ip, port, hostname)
    stream.sendall(
        (
            f"GET /echo HTTP/1.1\r\nHost: {hostname}\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
    )
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = stream.recv(1)
        assert chunk, "closed before WebSocket handshake"
        response += chunk
        assert len(response) < 8192
    assert b" 101 " in response, response
    return stream


def exact(stream, count):
    data = b""
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        assert chunk, "WebSocket closed unexpectedly"
        data += chunk
    return data


def echo(stream):
    stream.sendall(
        b"\x81\x84abcd" + bytes(c ^ m for c, m in zip(b"echo", b"abcd", strict=False))
    )
    assert exact(stream, 6) == b"\x81\x04echo"


def closed(stream):
    stream.settimeout(40)
    try:
        data = stream.recv(2)
        assert not data or data[0] & 15 == 8, data
    except (ssl.SSLError, ConnectionError):
        pass


def main():
    mode, ip, port, hostname = sys.argv[1:5]
    if mode == "http":
        print(json.dumps(request(ip, port, hostname)))
    elif mode == "reject":
        try:
            status, _ = request(ip, port, hostname)
            assert status != 200, "unexpected successful route"
        except (ssl.SSLError, ConnectionError, http.client.HTTPException):
            pass
        print("PASS undeclared SNI rejected")
    elif mode == "blocked":
        try:
            with socket.create_connection((ip, int(port)), timeout=4):
                raise AssertionError("unpermitted client reached application port")
        except (TimeoutError, ConnectionRefusedError):
            pass
        print("PASS unpermitted client blocked by network policy")
    elif mode == "disabled":
        with socket.socket() as stream:
            stream.settimeout(4)
            result = stream.connect_ex((ip, int(port)))
            assert result == errno.ECONNREFUSED, (ip, result)
        print("PASS disabled listener refuses TCP from the node network")
    elif mode == "gateway":
        status, body = request(
            ip,
            port,
            hostname,
            context=ssl._create_unverified_context(),
            authorization=None,
        )
        assert status == 200 and body["boot"], (status, body)
        print("PASS gateway-mediated application ingress with listener disabled")
    elif mode == "headers":
        status, body = request(ip, port, hostname)
        assert status == 200, (status, body)
        headers = {k.lower(): v for k, v in body["headers"].items()}
        assert headers["host"] == hostname
        assert headers["origin"] == "https://" + hostname
        assert headers["cookie"] == "app_session=fixture"
        assert "authorization" not in headers
        assert "x-openshell-principal" not in headers
        status, _ = request(ip, port, hostname, "different.services.example.com")
        assert status in (400, 421), status
        print(
            "PASS public authority/cookies preserved, credentials stripped, mismatched Host rejected"
        )
    elif mode == "bearer":
        status, body = request(ip, port, hostname)
        assert status == 200
        headers = {k.lower(): v for k, v in body["headers"].items()}
        assert headers["authorization"] == "Bearer application-test-token"
        print("PASS explicitly configured bearer passthrough")
    elif mode in ("withdraw", "takeover", "expire"):
        with (
            websocket(ip, port, hostname) as affected,
            websocket(*sys.argv[5:8]) as unaffected,
        ):
            echo(affected)
            echo(unaffected)
            time.sleep(35)
            echo(affected)
            echo(unaffected)
            print(
                "READY: quiet WebSockets survived beyond freshness window", flush=True
            )
            closed(affected)
            if mode != "expire":
                echo(unaffected)
            else:
                closed(unaffected)
            print(
                "PASS affected streams closed"
                + ("; unrelated stream survived" if mode != "expire" else "")
            )
    else:
        raise ValueError(mode)


if __name__ == "__main__":
    main()
