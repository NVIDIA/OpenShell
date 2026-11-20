#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""A corporate forward proxy for tests.

It does what a strict corporate proxy does, all at once:

- serves its listener over TLS, with a certificate signed by its own CA;
- requires Basic auth on every CONNECT;
- intercepts the TLS inside every tunnel, re-signing it with the same
  certificate, and opens its own unverified TLS connection to the target.

It appends one JSON line per CONNECT to the log, which tests read to see what
went through the proxy:

    {"time": 1.0, "target": "10.0.2.15:41234", "auth": "ok", "result": "intercepted"}

`auth` is `ok`, `missing` or `wrong`. `result` is `rejected` (407),
`dial_failed` (502), `client_tls_failed` (the client didn't accept the
proxy's certificate), `upstream_tls_failed` or `intercepted`. The log never
holds credentials.
"""

import argparse
import asyncio
import base64
import json
import ssl
import time
from pathlib import Path

MAX_HEAD = 65536
DIAL_TIMEOUT = 10
HANDSHAKE_TIMEOUT = 10
CHUNK = 65536


class Proxy:
    def __init__(self, args):
        credentials = Path(args.auth_file).read_text(encoding="utf-8").strip()
        self.expected_auth = "Basic " + base64.b64encode(credentials.encode()).decode()
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.load_cert_chain(args.cert, args.key)
        self.upstream_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.upstream_context.check_hostname = False
        self.upstream_context.verify_mode = ssl.CERT_NONE
        self.log_file = Path(args.log).open("a", encoding="utf-8")  # noqa: SIM115

    def log(self, target, auth, result, **extra):
        entry = {"time": time.time(), "target": target, "auth": auth, "result": result}
        entry.update(extra)
        self.log_file.write(json.dumps(entry) + "\n")
        self.log_file.flush()

    async def handle(self, reader, writer):
        try:
            await self.connect(reader, writer)
        except (
            OSError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            ssl.SSLError,
        ):
            pass
        finally:
            writer.close()

    async def connect(self, reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            writer.write(
                b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return
        target = parts[1]
        auth = "missing"
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "proxy-authorization":
                auth = "ok" if value.strip() == self.expected_auth else "wrong"
        if auth != "ok":
            self.log(target, auth, "rejected")
            writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b'Proxy-Authenticate: Basic realm="corp"\r\n'
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return

        host, _, port = target.rpartition(":")
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host.strip("[]"), int(port)), DIAL_TIMEOUT
            )
        except (OSError, ValueError, TimeoutError) as error:
            self.log(target, auth, "dial_failed", error=repr(error))
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return

        try:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            # TLS inside the listener's TLS. asyncio supports this from Python
            # 3.11; ssl.SSLSocket can't be wrapped a second time.
            try:
                await writer.start_tls(
                    self.server_context, ssl_handshake_timeout=HANDSHAKE_TIMEOUT
                )
            except (OSError, ssl.SSLError, TimeoutError) as error:
                self.log(target, auth, "client_tls_failed", error=repr(error))
                return
            try:
                await upstream_writer.start_tls(
                    self.upstream_context, ssl_handshake_timeout=HANDSHAKE_TIMEOUT
                )
            except (OSError, ssl.SSLError, TimeoutError) as error:
                self.log(target, auth, "upstream_tls_failed", error=repr(error))
                return
            self.log(target, auth, "intercepted")
            await relay(reader, writer, upstream_reader, upstream_writer)
        finally:
            upstream_writer.close()


async def pipe(reader, writer):
    while chunk := await reader.read(CHUNK):
        writer.write(chunk)
        await writer.drain()


async def relay(client_reader, client_writer, upstream_reader, upstream_writer):
    tasks = [
        asyncio.ensure_future(pipe(client_reader, upstream_writer)),
        asyncio.ensure_future(pipe(upstream_reader, client_writer)),
    ]
    # TLS streams can't half-close, so the tunnel ends when either side does.
    _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def ignore_disconnects(loop, context):
    # Probes and clients that drop the listener's TLS handshake would
    # otherwise fill the journal.
    if isinstance(context.get("exception"), (OSError, ssl.SSLError)):
        return
    loop.default_exception_handler(context)


async def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument(
        "--cert", required=True, help="PEM certificate chain, leaf first"
    )
    parser.add_argument("--key", required=True)
    parser.add_argument("--auth-file", required=True, help="a user:password file")
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    proxy = Proxy(args)
    asyncio.get_running_loop().set_exception_handler(ignore_disconnects)
    server = await asyncio.start_server(
        proxy.handle,
        args.listen,
        args.port,
        ssl=proxy.server_context,
        ssl_handshake_timeout=HANDSHAKE_TIMEOUT,
        limit=MAX_HEAD,
    )
    print(f"corporate proxy listening on {args.listen}:{args.port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
