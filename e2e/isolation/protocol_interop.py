# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# /// script
# requires-python = ">=3.11"
# dependencies = ["grpcio==1.78.0", "grpcio-tools==1.78.0", "cryptography==46.0.7"]
# [tool.uv]
# exclude-newer = "2026-10-08T00:00:00Z"
# ///
"""Protocol interoperability fixture, not a production isolation backend.

Run with uv run e2e/isolation/protocol_interop.py target/debug/openshell-supervisor.
Uses generated public gRPC bindings and independently implements JSON/framing.
The fixture simulates enforcement evidence and uses a fixed test bearer;
it does not provide isolation or exercise JWT validation.
"""

import asyncio
import datetime
import hashlib
import json
import os
import signal
import struct
import sys
import tempfile
import traceback
import uuid
from collections import Counter
from pathlib import Path

import grpc
import grpc_tools
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from grpc_tools import protoc

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "a" * 32
PAYLOAD = b"external-actor-v1\x00\xffopaque-resource"


def frame(value):
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    return struct.pack(">I", len(payload)) + payload


def canonical_request(envelope):
    request = dict(envelope["request"])
    if "exec_expires_at_unix_ms" in envelope:
        request["exec_expires_at_unix_ms"] = envelope["exec_expires_at_unix_ms"]
    return json.dumps(
        request, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def check_vectors():
    vectors = json.loads((ROOT / "proto/sandbox_protocol/v1/vectors.json").read_text())
    assert vectors["version"] == "1.0"
    for vector in vectors["requests"]:
        canonical = canonical_request(vector["envelope"])
        assert canonical == vector["canonical_request"].encode()
        assert (
            hashlib.sha256(canonical).hexdigest()
            == vector["envelope"]["payload_digest"]
        )
        data = bytes.fromhex(vector["frame_hex"])
        assert struct.unpack(">I", data[:4])[0] == len(data) - 4
        assert json.loads(data[4:]) == vector["envelope"]
    print("PASS: public request digest and framing vectors")


async def main(binary):
    check_vectors()
    with tempfile.TemporaryDirectory(prefix="openshell-interop-") as directory:
        directory = Path(directory)
        assert (
            protoc.main(
                [
                    "protoc",
                    f"-I{ROOT / 'proto'}",
                    f"-I{Path(grpc_tools.__file__).parent / '_proto'}",
                    f"--python_out={directory}",
                    f"--grpc_python_out={directory}",
                    *[
                        str(ROOT / "proto" / name)
                        for name in [
                            "options.proto",
                            "extension.proto",
                            "isolation_backend.proto",
                            "sandbox_protocol.proto",
                        ]
                    ],
                ]
            )
            == 0
        )
        sys.path.insert(0, str(directory))
        import extension_pb2 as extension
        import isolation_backend_pb2 as control
        import isolation_backend_pb2_grpc as control_rpc
        import sandbox_protocol_pb2 as stream
        import sandbox_protocol_pb2_grpc as stream_rpc

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "backend.test")])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("backend.test")]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        ca_pem = cert.public_bytes(serialization.Encoding.PEM)
        ca_key = key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("backend.test")]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        session = str(uuid.uuid4())
        identity = {
            "uid": 1000,
            "gid": 1000,
            "supplementary_gids": [],
            "source": "fixture",
            "resource_digest": "fixture-rootfs",
        }
        fence = {
            "generation": "interop-generation",
            "established": [
                "default_deny_egress",
                "no_unmanaged_egress_path",
                "revocation_verified",
                "controller_loss_fails_closed",
            ],
            "evidence_digest": "1" * 64,
        }
        events = []
        opened_peers = set()
        replay = {}
        confirmed = False
        process = None
        finished = asyncio.Event()
        started = asyncio.Event()
        handle = "external-route"

        class Backend(
            control_rpc.IsolationBackendServicer,
            stream_rpc.DelegatedIsolationBoundaryServicer,
        ):
            async def authenticated(self, context):
                assert (
                    dict(context.invocation_metadata()).get("authorization")
                    == f"Bearer {TOKEN}"
                )

            async def GetCapabilities(self, request, context):
                assert request.supervisor.protocol_version.major == 1
                assert (
                    "openshell.isolation.contract"
                    in request.supervisor.supported_capabilities
                )
                assert "authorization" not in dict(context.invocation_metadata())
                events.append("negotiate")
                return control.GetIsolationCapabilitiesResponse(
                    backend=extension.PeerMetadata(
                        protocol_version=extension.ProtocolVersion(major=1, minor=0),
                        implementation_name="python-interop",
                        implementation_version="1.0",
                        supported_capabilities=["openshell.isolation.contract"],
                        required_capabilities=["openshell.isolation.contract"],
                    )
                )

            async def OpenBoundary(self, request, context):
                await self.authenticated(context)
                assert request.backend_name == "python-external"
                assert request.driver_descriptor == PAYLOAD
                assert (
                    request.sandbox_id,
                    request.generation_id,
                    request.session_id,
                ) == ("interop-sandbox", "interop-generation", session)
                opened_peers.add(context.peer())
                events.append("open")
                return control.OpenBoundaryResponse(boundary_id=handle, outcome=1)

            async def Exchange(self, requests, context):
                try:
                    async for chunk in self.exchange(requests, context):
                        yield chunk
                except Exception:
                    traceback.print_exc()
                    raise

            async def exchange(self, requests, context):
                nonlocal confirmed, process
                await self.authenticated(context)
                assert context.peer() in opened_peers
                requests = aiter(requests)
                binding = await anext(requests)
                assert (
                    binding.WhichOneof("payload") == "boundary_id"
                    and binding.boundary_id == handle
                )
                await context.send_initial_metadata(())
                data = bytearray()
                async for chunk in requests:
                    assert chunk.WhichOneof("payload") == "data"
                    data.extend(chunk.data)
                    if len(data) >= 4:
                        length = struct.unpack(">I", data[:4])[0]
                        assert 0 < length <= 1048576
                        if len(data) >= 4 + length:
                            break
                length = struct.unpack(">I", data[:4])[0]
                assert 0 < length <= 1048576
                envelope = json.loads(data[4 : 4 + length])
                request = envelope["request"]
                canonical = canonical_request(envelope)
                assert (
                    hashlib.sha256(canonical).hexdigest() == envelope["payload_digest"]
                )
                operation = request["operation"]
                events.append(operation)
                if envelope["request_id"] in replay:
                    digest, response = replay[envelope["request_id"]]
                    assert digest == envelope["payload_digest"]
                elif operation == "discover_policy":
                    response = {
                        "result": "image_policy",
                        "yaml": None,
                        "invalid": False,
                    }
                elif operation == "attach":
                    response = {
                        "result": "attached",
                        "snapshot": {
                            "generation": "interop-generation",
                            "processes": [],
                        },
                    }
                elif operation == "confirm":
                    assert "attach" in events
                    confirmed = True
                    prop = {"enforced": True, "mechanism": "interop-fixture"}
                    response = {
                        "result": "confirmed",
                        "confirmation": {
                            "generation": "interop-generation",
                            "session_id": session,
                            "identity": identity,
                            "outer_fence": fence,
                            "resource_claims": {},
                            "authenticated_supervisor": True,
                            "runtime_exit_terminates_workload": True,
                            "properties": dict.fromkeys(
                                [
                                    "filesystem_confinement",
                                    "egress_interception",
                                    "request_attribution",
                                    "privilege_floor",
                                ],
                                prop,
                            ),
                            "backend_audit": {"fixture": "python-no-linux-audit"},
                        },
                    }
                elif operation == "start_agent":
                    assert confirmed
                    spec = request["spec"]
                    assert spec["program"] == "/bin/sleep" and spec["args"] == ["60"]
                    process = await asyncio.create_subprocess_exec(
                        spec["program"], *spec["args"]
                    )
                    started.set()
                    response = {
                        "result": "started",
                        "process_id": "external-main",
                        "provider_env_revision": request["provider_env_revision"],
                        "provider_env_generation": 1,
                    }
                elif operation == "attach_process":
                    response = {"result": "process_attached", "terminal": False}
                elif operation == "signal":
                    assert request["signal"] == "term"
                    process.terminate()
                    response = {"result": "signaled"}
                elif operation == "wait":
                    code = await process.wait()
                    response = {
                        "result": "exited",
                        "status": {
                            "kind": "signaled" if code < 0 else "exited",
                            "value": abs(code),
                        },
                    }
                elif operation == "accept_network":
                    await finished.wait()
                    response = {
                        "result": "error",
                        "kind": "terminated",
                        "message": "fixture boundary ended",
                    }
                elif operation == "open_mediation":
                    response = {"result": "mediation_ready"}
                elif operation == "terminate_boundary":
                    assert process.returncode is not None
                    finished.set()
                    response = {"result": "boundary_terminated"}
                else:
                    raise AssertionError(f"unexpected operation {operation}")
                replay[envelope["request_id"]] = envelope["payload_digest"], response
                yield stream.DelegatedBoundaryChunk(
                    data=frame(
                        {"request_id": envelope["request_id"], "response": response}
                    )
                )
                if operation == "open_mediation":
                    await finished.wait()
                if operation == "attach_process":
                    status = await process.wait()
                    payload = json.dumps(
                        {
                            "kind": "signaled" if status < 0 else "exited",
                            "value": abs(status),
                        },
                        separators=(",", ":"),
                    ).encode()
                    yield stream.DelegatedBoundaryChunk(
                        data=bytes([3]) + struct.pack(">I", len(payload)) + payload
                    )

            async def Mediate(self, requests, context):
                async for chunk in self.Exchange(requests, context):
                    yield chunk

        server = grpc.aio.server()
        backend = Backend()
        control_rpc.add_IsolationBackendServicer_to_server(backend, server)
        stream_rpc.add_DelegatedIsolationBoundaryServicer_to_server(backend, server)
        port = server.add_secure_port(
            "127.0.0.1:0", grpc.ssl_server_credentials([(key_pem, cert_pem)])
        )
        await server.start()
        registration = {
            "backends": [
                {
                    "name": "python-external",
                    "endpoint": {
                        "kind": "tcp",
                        "authority": f"backend.test:{port}",
                        "addresses": [f"127.0.0.1:{port}"],
                    },
                }
            ]
        }
        launch = {
            "backend_name": "python-external",
            "sandbox_id": "interop-sandbox",
            "generation": "interop-generation",
            "session_id": session,
            "workload_identity": identity,
            "resource_claims": {},
            "outer_fence": fence,
            "tls": {"server_name": "backend.test", "trust_anchor_pem": ca_pem.decode()},
        }
        auth = {
            "session_id": session,
            "runtime_generation": "interop-generation",
            "session_rotation": 1,
            "auth_epoch": 1,
            "gateway_token": TOKEN,
            "gateway_expires_at": 0,
            "sandbox_token": TOKEN,
            "sandbox_expires_at": 0,
        }
        for name, value in [
            ("registration.json", registration),
            ("launch.json", launch),
            ("auth.json", auth),
        ]:
            (directory / name).write_text(json.dumps(value))
        (directory / "descriptor").write_bytes(PAYLOAD)
        (directory / "policy.yaml").write_text("network_policies: {}\n")
        environment = dict(
            {
                name: value
                for name, value in os.environ.items()
                if not name.startswith("OPENSHELL_")
            },
            OPENSHELL_ADMITTED_ISOLATION_BACKEND="python-external",
            OPENSHELL_TELEMETRY_ENABLED="false",
            OPENSHELL_PROXY_TLS_DIR=str(directory / "tls"),
        )
        supervisor = await asyncio.create_subprocess_exec(
            str(Path(binary).resolve()),
            "--health-socket-path",
            str(directory / "ready.sock"),
            "--sandbox-id",
            "interop-sandbox",
            "--policy-rules",
            str(ROOT / "crates/openshell-supervisor-network/data/sandbox-policy.rego"),
            "--policy-data",
            str(directory / "policy.yaml"),
            "--isolation-backends-file",
            str(directory / "registration.json"),
            "--boundary-launch-file",
            str(directory / "launch.json"),
            "--backend-descriptor-file",
            str(directory / "descriptor"),
            "--auth-bundle-file",
            str(directory / "auth.json"),
            "--",
            "/bin/sleep",
            "60",
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output_task = asyncio.create_task(supervisor.stdout.read())

        async def shutdown_when_ready():
            await started.wait()
            while not (directory / "ready.sock").exists():
                assert supervisor.returncode is None, (await output_task).decode()
                await asyncio.sleep(0.01)
            supervisor.send_signal(signal.SIGTERM)
            await supervisor.wait()

        try:
            await asyncio.wait_for(shutdown_when_ready(), timeout=30)
            output = await output_task
            assert supervisor.returncode == 128 + signal.SIGTERM, output.decode()
            assert finished.is_set(), output.decode()
            assert events.index("confirm") < events.index("start_agent")
            print(
                "PASS: stock supervisor → registered Python backend → workload → acknowledged cleanup"
            )
        finally:
            if supervisor.returncode is None:
                supervisor.kill()
                await supervisor.wait()
                print((await output_task).decode(), file=sys.stderr)
                print(Counter(events), events[-10:], file=sys.stderr)
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            await server.stop(0)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
