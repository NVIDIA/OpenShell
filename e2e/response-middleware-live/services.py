# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real HTTP upstream and configurable external gRPC response middleware."""

import concurrent.futures
import gzip
import hashlib
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import grpc
import supervisor_middleware_pb2 as p
import supervisor_middleware_pb2_grpc as rpc
from google.protobuf.json_format import MessageToDict
from run import OUT as ROOT

LOCK = threading.Lock()
LOG = (ROOT / "events.jsonl").open("a", buffering=1)


def log(**fields):
    with LOCK:
        LOG.write(json.dumps(dict(time=time.time(), **fields)) + "\n")


class Middleware(rpc.SupervisorMiddlewareServicer, rpc.HttpResponsePreReturnServicer):
    def __init__(self, name, limit):
        self.name, self.limit = name, limit

    def Describe(self, _req, _ctx):
        return p.MiddlewareManifest(
            name=self.name,
            service_version="live-test",
            bindings=[
                p.MiddlewareBinding(operation=3, phase=2, max_payload_bytes=self.limit)
            ],
        )

    def ValidateConfig(self, _req, _ctx):
        return p.ValidateConfigResponse(valid=True)

    def Evaluate(self, events, ctx):
        config, path, request_id = {}, "", ""
        for event in events:
            kind = event.WhichOneof("event")
            if kind == "preflight":
                pf = event.preflight
                config = MessageToDict(pf.config)
                path, request_id = pf.target.path, pf.context.request_id
                action = config.get("preflight", "inspect")
                if not config.get("quiet"):
                    log(
                        service=self.name,
                        request_id=request_id,
                        path=path,
                        kind=kind,
                        modes=list(pf.permitted_body_modes),
                        limit=pf.max_payload_bytes,
                        headers=MessageToDict(pf).get("headers", []),
                        config=config,
                    )
                if action == "timeout":
                    time.sleep(0.35)
                if action == "abort":
                    ctx.abort(grpc.StatusCode.UNAVAILABLE, "fixture unavailable")
                if action in ("skip", "block_delivery"):
                    result = p.HttpResponsePreflightResult(
                        **{action: {}},
                        reason_code="fixture_block"
                        if action == "block_delivery"
                        else "",
                    )
                else:
                    mutations = []
                    if "header" in config:
                        mutations.append(
                            p.HeaderMutation(
                                write=p.WriteHeader(
                                    name=config.get("header_name", "x-live-test"),
                                    value=config["header"],
                                    on_existing=2,
                                )
                            )
                        )
                    result = p.HttpResponsePreflightResult(
                        inspect=p.HttpResponsePreflightInspect(
                            body_mode=int(config.get("mode", 1)),
                            header_mutations=mutations,
                        )
                    )
                yield p.HttpResponseEventResult(preflight_result=result)
            elif kind == "body":
                unit = event.body
                if not config.get("quiet"):
                    log(
                        service=self.name,
                        request_id=request_id,
                        path=path,
                        kind=kind,
                        seq=unit.sequence,
                        final=unit.end_of_stream,
                        length=len(unit.data),
                        sample=unit.data[:120].decode(errors="replace"),
                        sha256=hashlib.sha256(unit.data).hexdigest(),
                    )
                action = config.get("body", "pass_through")
                if config.get("block_seq") and unit.sequence < config["block_seq"]:
                    action = "pass_through"
                if action == "timeout":
                    time.sleep(0.35)
                    action = "pass_through"
                if action == "abort":
                    ctx.abort(grpc.StatusCode.UNAVAILABLE, "fixture unavailable")
                data = unit.data.replace(
                    config.get("find", "secret").encode(),
                    config.get("replace", "[REDACTED]").encode(),
                )
                if "append" in config:
                    data += config["append"].encode()
                if config.get("delete"):
                    data = b""
                if action == "invalid_sequence":
                    result = p.HttpResponseBodyResult(
                        sequence=unit.sequence + 10, pass_through={}
                    )
                elif action == "skip_remaining":
                    nested = (
                        {"transform": {"data": data}}
                        if config.get("skip_transform")
                        else {"pass_through": {}}
                    )
                    result = p.HttpResponseBodyResult(
                        sequence=unit.sequence,
                        skip_remaining=p.HttpResponseBodySkipRemaining(**nested),
                    )
                else:
                    payload = {"data": data} if action == "transform" else {}
                    result = p.HttpResponseBodyResult(
                        sequence=unit.sequence,
                        **{action: payload},
                        reason_code="fixture_block"
                        if action == "block_delivery"
                        else "",
                    )
                yield p.HttpResponseEventResult(body_result=result)
            elif kind == "trailers":
                if not config.get("quiet"):
                    log(
                        service=self.name,
                        request_id=request_id,
                        path=path,
                        kind=kind,
                        trailers=MessageToDict(event.trailers),
                    )
                mutations = (
                    [
                        p.HeaderMutation(
                            write=p.WriteHeader(
                                name="x-check", value="changed", on_existing=2
                            )
                        )
                    ]
                    if config.get("trailer")
                    else []
                )
                yield p.HttpResponseEventResult(
                    trailers_result=p.HttpResponseTrailersResult(
                        trailer_mutations=mutations
                    )
                )
            elif kind == "session_end":
                if not config.get("quiet"):
                    log(
                        service=self.name,
                        request_id=request_id,
                        path=path,
                        kind=kind,
                        end=MessageToDict(event.session_end),
                    )


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url = urlparse(self.path)
        path = url.path
        size = int(parse_qs(url.query).get("size", [0])[0])
        data = (b"x" * size) if size else b"alpha secret omega\n"
        if path == "/empty":
            data = b""
        status = 204 if path == "/bodyless" else 206 if path == "/range" else 200
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Origin", "fixture")
        self.send_header("ETag", '"original"')
        if path == "/encoded":
            data = gzip.compress(data)
            self.send_header("Content-Encoding", "gzip")
        if path == "/range":
            self.send_header("Content-Range", "bytes 0-17/18")
        if path == "/no-transform":
            self.send_header("Cache-Control", "no-transform")
        chunked = path in ("/chunked", "/slow", "/split", "/trailers")
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
            if path == "/trailers":
                self.send_header("Trailer", "x-check")
        else:
            self.send_header("Content-Length", str(len(data)) if status != 204 else "0")
        self.end_headers()
        if self.command == "HEAD" or status == 204:
            return
        try:
            if chunked:
                chunks = (
                    [b"sec", b"ret"]
                    if path == "/split"
                    else [b"alpha ", b"secret ", b"omega\n"]
                    if path == "/slow"
                    else [data]
                )
                for i, chunk in enumerate(chunks):
                    if i and path in ("/slow", "/split"):
                        time.sleep(0.06)
                    self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(
                    b"0\r\nx-check: original\r\n\r\n"
                    if path == "/trailers"
                    else b"0\r\n\r\n"
                )
            else:
                self.wfile.write(data)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    servers = []
    for i, limit in enumerate([262144, 262144, 262144, 32]):
        server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=32))
        impl = Middleware(f"fixture-{i + 1}", limit)
        rpc.add_SupervisorMiddlewareServicer_to_server(impl, server)
        rpc.add_HttpResponsePreReturnServicer_to_server(impl, server)
        assert server.add_insecure_port(f"0.0.0.0:{18191 + i}")
        server.start()
        servers.append(server)
    print("Middleware ready on 18191-18194; upstream on 18081", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 18081), Upstream).serve_forever()
