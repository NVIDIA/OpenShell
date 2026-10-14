# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "grpcio==1.78.0",
#   "grpcio-tools==1.78.0",
#   "protobuf==6.33.5",
#   "wasmtime==49.0.0",
# ]
# ///
"""Partial external isolation backend and a separate, local WASI guest runner.

This is deliberately not a production supervisor backend. Its protobuf endpoint
reserves resources but cannot authorize guest execution. See README.md for gaps.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import secrets
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import grpc
import grpc_tools
import wasmtime
from grpc_tools import protoc

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BACKEND = "example-wasmtime"
CAPABILITY = "openshell.example.wasi-prototype"
MAX_MODULE = 4 * 1024 * 1024
MAX_OUTPUT = 64 * 1024


def generate(directory: str):
    """Generate from repository protos into temporary storage, never the tree."""
    includes = [ROOT / "proto"]
    result = protoc.main(
        [
            "protoc",
            *(f"-I{path}" for path in includes),
            f"-I{Path(grpc_tools.__file__).parent / '_proto'}",
            f"--python_out={directory}",
            f"--grpc_python_out={directory}",
            "options.proto",
            "extension.proto",
            "sandbox_backend.proto",
            "sandbox_protocol.proto",
        ]
    )
    if result:
        raise RuntimeError("protobuf generation failed")
    sys.path.insert(0, directory)
    # Keep Python from emitting bytecode into the temporary generated directory.
    sys.dont_write_bytecode = True
    return tuple(
        importlib.import_module(name)
        for name in (
            "extension_pb2",
            "sandbox_backend_pb2",
            "sandbox_backend_pb2_grpc",
            "sandbox_protocol_pb2",
            "sandbox_protocol_pb2_grpc",
        )
    )


def read_module(path: Path) -> bytes:
    with path.open("rb") as source:
        payload = source.read(MAX_MODULE + 1)
    if len(payload) > MAX_MODULE:
        raise ValueError("module exceeds the 4 MiB prototype limit")
    return bytes(wasmtime.wat2wasm(payload)) if path.suffix == ".wat" else payload


@dataclass(frozen=True)
class Provisioned:
    """Trusted local provisioning. Credentials never come from request claims."""

    sandbox_id: str
    session_id: str
    generation_id: str
    token: str
    module: bytes

    @property
    def descriptor(self) -> bytes:
        return json.dumps(
            {"module_sha256": hashlib.sha256(self.module).hexdigest()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class Endpoint:
    def __init__(self, protos, provisioned: Provisioned):
        self.extension, self.control, _, _, _ = protos
        self.provisioned = provisioned
        self.lock = threading.Lock()
        self.boundary_id: str | None = None

    def metadata(self):
        return self.extension.PeerMetadata(
            protocol_version=self.extension.ProtocolVersion(major=1, minor=0),
            implementation_name=BACKEND,
            implementation_version="0.0.0",
            supported_capabilities=[CAPABILITY],
            required_capabilities=[CAPABILITY],
        )

    def authenticate(self, context):
        values = [
            item.value
            for item in context.invocation_metadata()
            if item.key == "authorization"
        ]
        if len(values) != 1 or not secrets.compare_digest(
            values[0], f"Bearer {self.provisioned.token}"
        ):
            context.abort(
                grpc.StatusCode.UNAUTHENTICATED, "invalid prototype credential"
            )

    def Describe(self, request, context):
        local = self.metadata()
        remote = request.supervisor
        if (
            not remote.HasField("protocol_version")
            or remote.protocol_version.major != 1
            or not set(local.required_capabilities)
            <= set(remote.supported_capabilities)
            or not set(remote.required_capabilities)
            <= set(local.supported_capabilities)
        ):
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "partial WASI prototype does not implement the base isolation contract",
            )
        return self.control.DescribeSandboxBackendResponse(backend=local)

    def OpenBoundary(self, request, context):
        self.authenticate(context)
        provisioned = self.provisioned
        if (
            request.sandbox_id != provisioned.sandbox_id
            or request.session_id != provisioned.session_id
            or request.generation_id != provisioned.generation_id
            or request.backend_name != BACKEND
        ):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "launch identity mismatch")
        # Exact bytes deliberately form the immutable prototype descriptor.
        # No request-controlled module path or host path is accepted.
        if request.driver_descriptor != provisioned.descriptor:
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED, "provisioned module mismatch"
            )
        with self.lock:
            if self.boundary_id is None:
                self.boundary_id = secrets.token_hex(32)
            boundary_id = self.boundary_id
        # Only reserve the compiled-input identity: do not instantiate here.
        # Instantiation can itself execute a WebAssembly start function.
        return self.control.OpenBoundaryResponse(
            boundary_id=boundary_id,
            outcome=self.control.OpenBoundaryResponse.LAUNCH_OUTCOME_FRESH,
        )

    def route(self, requests, context):
        self.authenticate(context)
        first = next(requests, None)
        if (
            first is None
            or first.WhichOneof("payload") != "boundary_id"
            or not first.boundary_id
        ):
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT, "first frame must identify a boundary"
            )
        with self.lock:
            expected = self.boundary_id
        if expected is None or not secrets.compare_digest(first.boundary_id, expected):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "unknown boundary handle")

    def Exchange(self, requests, context):
        self.route(requests, context)
        context.abort(
            grpc.StatusCode.UNIMPLEMENTED,
            "WASI prototype has no attach/confirm/start implementation; no guest was run",
        )

    def Mediate(self, requests, context):
        self.route(requests, context)
        context.abort(
            grpc.StatusCode.UNIMPLEMENTED,
            "no TCP/DNS host capability is granted; mediation is not implemented",
        )

    def SuspendBoundary(self, _request, context):
        self.authenticate(context)
        context.abort(
            grpc.StatusCode.UNIMPLEMENTED, "WASI memory snapshots are not implemented"
        )

    def ResumeBoundary(self, _request, context):
        self.authenticate(context)
        context.abort(
            grpc.StatusCode.UNIMPLEMENTED, "WASI memory restoration is not implemented"
        )


def start_server(protos, provisioned: Provisioned):
    _, _, control_grpc, _, stream_grpc = protos
    endpoint = Endpoint(protos, provisioned)
    server = grpc.server(
        ThreadPoolExecutor(max_workers=4),
        options=[
            ("grpc.max_receive_message_length", 1024 * 1024),
        ],
    )
    control_grpc.add_SandboxBackendServicer_to_server(endpoint, server)
    stream_grpc.add_SandboxBoundaryServicer_to_server(endpoint, server)
    port = server.add_insecure_port("127.0.0.1:0")
    if not port:
        raise RuntimeError("cannot bind loopback server")
    server.start()
    return server, f"127.0.0.1:{port}"


@dataclass(frozen=True)
class GuestResult:
    status: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    module_sha256: str


class Guest:
    """Local experimental runner, intentionally unreachable through the RPCs."""

    def __init__(self, module: bytes, workspace: Path, fuel: int = 1_000_000):
        config = wasmtime.Config()
        config.consume_fuel = True
        config.epoch_interruption = True
        self.engine = wasmtime.Engine(config)
        self.module = wasmtime.Module(self.engine, module)
        self.digest = hashlib.sha256(module).hexdigest()
        self.workspace = workspace.resolve(strict=True)
        self.fuel = fuel
        self.started = threading.Event()
        self.cancelled = threading.Event()

    def terminate(self):
        self.cancelled.set()
        self.engine.increment_epoch()

    def run(self) -> GuestResult:
        stdout = bytearray()
        stderr = bytearray()

        def capture(target):
            def write(payload):
                if len(target) + len(payload) > MAX_OUTPUT:
                    return -1
                target.extend(payload)
                return len(payload)

            return write

        with wasmtime.Store(self.engine) as store:
            store.set_limits(
                memory_size=16 * 1024 * 1024,
                table_elements=1024,
                instances=1,
                tables=1,
                memories=1,
            )
            store.set_fuel(self.fuel)
            store.set_epoch_deadline(1)
            wasi = wasmtime.WasiConfig()
            wasi.argv = ["/work/guest.wasm"]
            # No environment or stdin inheritance, and no network descriptors.
            wasi.preopen_dir(str(self.workspace), "/work", fs_mutable=False)
            wasi.stdout_custom = capture(stdout)
            wasi.stderr_custom = capture(stderr)
            store.set_wasi(wasi)
            linker = wasmtime.Linker(self.engine)
            linker.define_wasi()
            if self.cancelled.is_set():
                return GuestResult("terminated", None, b"", b"", self.digest)
            self.started.set()
            try:
                # This is the first operation that can execute guest code.
                instance = linker.instantiate(store, self.module)
                instance.exports(store)["_start"](store)
                status, code = "exited", 0
            except wasmtime.ExitTrap as error:
                status, code = "exited", error.code
            except wasmtime.Trap as error:
                if error.trap_code == wasmtime.TrapCode.INTERRUPT:
                    status = "terminated"
                elif error.trap_code == wasmtime.TrapCode.OUT_OF_FUEL:
                    status = "fuel_exhausted"
                else:
                    status = "trapped"
                code = None
            except wasmtime.WasmtimeError:
                # Includes unsupported imports: no fallback host function.
                status, code = "unsupported_module", None
        return GuestResult(status, code, bytes(stdout), bytes(stderr), self.digest)


def expect_rpc_error(call, status):
    try:
        call()
    except grpc.RpcError as error:
        if error.code() != status:
            raise AssertionError(
                f"expected {status}, got {error.code()}: {error.details()}"
            ) from error
    else:
        raise AssertionError(f"expected {status}")


def smoke(protos):
    _extension, control, control_grpc, stream, stream_grpc = protos
    payload = read_module(HERE / "guest.wat")
    provisioned = Provisioned(
        "sandbox-a", "session-a", "generation-a", secrets.token_hex(32), payload
    )
    # Run the endpoint in a separate interpreter: the client shares only wire
    # messages with it, not an in-process backend or generated service instance.
    temporary = tempfile.TemporaryDirectory(prefix="openshell-wasi-server-")
    token_file = Path(temporary.name) / "credential"
    token_file.write_text(provisioned.token)
    token_file.chmod(0o600)
    process = subprocess.Popen(
        [
            sys.executable,
            str(HERE / "example.py"),
            "serve",
            str(HERE / "guest.wat"),
            "--sandbox-id",
            provisioned.sandbox_id,
            "--session-id",
            provisioned.session_id,
            "--generation-id",
            provisioned.generation_id,
            "--token-file",
            str(token_file),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        announcement = json.loads(process.stdout.readline())
        address = announcement["endpoint"]
        assert announcement["backend_name"] == BACKEND
        assert announcement["descriptor"] == json.loads(provisioned.descriptor)
        with grpc.insecure_channel(address) as channel:
            grpc.channel_ready_future(channel).result(timeout=5)
            client = control_grpc.SandboxBackendStub(channel)
            streams = stream_grpc.SandboxBoundaryStub(channel)
            auth = [("authorization", f"Bearer {provisioned.token}")]
            peer = Endpoint(protos, provisioned).metadata()
            caps = client.Describe(
                control.DescribeSandboxBackendRequest(supervisor=peer), timeout=5
            )
            assert list(caps.backend.supported_capabilities) == [CAPABILITY]
            peer.required_capabilities[:] = ["openshell.sandbox.protocol"]
            expect_rpc_error(
                lambda: client.Describe(
                    control.DescribeSandboxBackendRequest(supervisor=peer), timeout=5
                ),
                grpc.StatusCode.FAILED_PRECONDITION,
            )
            print(
                "PASS negotiation: partial capability accepted; full supervisor contract rejected"
            )

            launch = control.OpenBoundaryRequest(
                sandbox_id=provisioned.sandbox_id,
                session_id=provisioned.session_id,
                generation_id=provisioned.generation_id,
                backend_name=BACKEND,
                driver_descriptor=provisioned.descriptor,
            )
            opened = client.OpenBoundary(launch, metadata=auth, timeout=5)
            retry = client.OpenBoundary(launch, metadata=auth, timeout=5)
            assert opened == retry and opened.boundary_id
            expect_rpc_error(
                lambda: client.OpenBoundary(launch, timeout=5),
                grpc.StatusCode.UNAUTHENTICATED,
            )
            for field, value in (
                ("sandbox_id", "sandbox-b"),
                ("session_id", "other-session"),
                ("generation_id", "stale"),
                ("backend_name", "openshell"),
                ("driver_descriptor", b"{}"),
            ):
                invalid = control.OpenBoundaryRequest()
                invalid.CopyFrom(launch)
                setattr(invalid, field, value)
                expect_rpc_error(
                    lambda invalid=invalid: client.OpenBoundary(
                        invalid, metadata=auth, timeout=5
                    ),
                    grpc.StatusCode.PERMISSION_DENIED,
                )
            print(
                "PASS binding: exact retry, credential, sandbox, session, generation, backend, module"
            )

            def exchange(first):
                return list(streams.Exchange(iter([first]), metadata=auth, timeout=5))

            expect_rpc_error(
                lambda: exchange(stream.BoundaryChunk(data=b"bad")),
                grpc.StatusCode.INVALID_ARGUMENT,
            )
            expect_rpc_error(
                lambda: exchange(stream.BoundaryChunk(boundary_id="other")),
                grpc.StatusCode.PERMISSION_DENIED,
            )
            expect_rpc_error(
                lambda: exchange(stream.BoundaryChunk(boundary_id=opened.boundary_id)),
                grpc.StatusCode.UNIMPLEMENTED,
            )
            expect_rpc_error(
                lambda: list(
                    streams.Mediate(
                        iter([stream.BoundaryChunk(boundary_id=opened.boundary_id)]),
                        metadata=auth,
                        timeout=5,
                    )
                ),
                grpc.StatusCode.UNIMPLEMENTED,
            )
            expect_rpc_error(
                lambda: client.SuspendBoundary(
                    control.SuspendBoundaryRequest(
                        boundary_id=opened.boundary_id,
                        session_id=provisioned.session_id,
                        generation_id=provisioned.generation_id,
                    ),
                    metadata=auth,
                    timeout=5,
                ),
                grpc.StatusCode.UNIMPLEMENTED,
            )
            expect_rpc_error(
                lambda: client.ResumeBoundary(
                    control.ResumeBoundaryRequest(launch=launch),
                    metadata=auth,
                    timeout=5,
                ),
                grpc.StatusCode.UNIMPLEMENTED,
            )
            print(
                "PASS routing: invalid handles rejected; lifecycle, mediation, suspend/resume unsupported"
            )
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()
        temporary.cleanup()

    with tempfile.TemporaryDirectory(prefix="openshell-wasi-smoke-") as directory:
        outer = Path(directory)
        workspace = outer / "workspace"
        workspace.mkdir()
        (workspace / "allowed.txt").write_text("workspace content\n")
        (outer / "secret.txt").write_text("outside secret\n")
        (workspace / "escape").symlink_to(outer / "secret.txt")
        result = Guest(payload, workspace).run()
        assert result.status == "exited" and result.exit_code == 0, result
        assert (
            result.stdout
            == b"workspace content\nescape denied\nsymlink denied\nwrite denied\n"
        ), result
        assert not (workspace / "new.txt").exists()
        print(
            "PASS real WASI: allowed file read; traversal, symlink escape, writes denied"
        )

        loop = bytes(
            wasmtime.wat2wasm('(module (func (export "_start") (loop $l br $l)))')
        )
        assert Guest(loop, workspace).run().status == "fuel_exhausted"
        memory = bytes(
            wasmtime.wat2wasm('(module (memory 257) (func (export "_start")))')
        )
        assert Guest(memory, workspace).run().status == "unsupported_module"
        network = bytes(
            wasmtime.wat2wasm(
                '(module (import "wasi:sockets/tcp" "create-socket" (func)) (func (export "_start")))'
            )
        )
        assert Guest(network, workspace).run().status == "unsupported_module"
        print(
            "PASS limits: infinite loop fuel exhausted; excess memory and socket import rejected"
        )

        guest = Guest(loop, workspace, fuel=1_000_000_000_000)
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(guest.run)
            assert guest.started.wait(timeout=5)
            guest.terminate()
            assert pending.result(timeout=5).status == "terminated"
        print("PASS termination: running guest interrupted by its backend-owned engine")
    print("Prototype smoke passed. No production supervisor workload was started.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "smoke", help="real gRPC contract checks and real WASI isolation checks"
    )
    runner = commands.add_parser(
        "run", help="local guest experiment; bypasses supervisor admission"
    )
    runner.add_argument("module", type=Path)
    runner.add_argument("--workspace", type=Path, required=True)
    server = commands.add_parser(
        "serve", help="partial, loopback-only protobuf endpoint"
    )
    server.add_argument("module", type=Path)
    server.add_argument("--sandbox-id", required=True)
    server.add_argument("--session-id", required=True)
    server.add_argument("--generation-id", required=True)
    server.add_argument("--token-file", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "run":
        result = Guest(read_module(args.module), args.workspace).run()
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        print(
            json.dumps(
                {
                    "status": result.status,
                    "exit_code": result.exit_code,
                    "module_sha256": result.module_sha256,
                }
            ),
            file=sys.stderr,
        )
        return 0 if result.status == "exited" and result.exit_code == 0 else 1
    with tempfile.TemporaryDirectory(prefix="openshell-wasi-proto-") as generated:
        protos = generate(generated)
        if args.command == "smoke":
            smoke(protos)
        else:
            if not all((args.sandbox_id, args.session_id, args.generation_id)):
                raise ValueError(
                    "sandbox, session, and generation identities must be nonempty"
                )
            token = args.token_file.read_text().strip()
            if len(token) < 32 or any(character.isspace() for character in token):
                raise ValueError(
                    "prototype credential must have at least 32 non-whitespace characters"
                )
            provisioned = Provisioned(
                args.sandbox_id,
                args.session_id,
                args.generation_id,
                token,
                read_module(args.module),
            )
            endpoint, address = start_server(protos, provisioned)
            print(
                json.dumps(
                    {
                        "endpoint": address,
                        "backend_name": BACKEND,
                        "descriptor": json.loads(provisioned.descriptor),
                    }
                ),
                flush=True,
            )
            try:
                endpoint.wait_for_termination()
            except KeyboardInterrupt:
                endpoint.stop(0).wait(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
