from __future__ import annotations

import importlib.resources
import os
import pathlib
import sys
import tempfile
import time

import grpc
from grpc_tools import protoc


DEFAULT_PROTO_DIR = pathlib.Path("/app/proto")
REPO_PROTO_DIR = pathlib.Path(__file__).resolve().parents[2] / "proto"
PROTO_DIR = pathlib.Path(os.environ.get("NAVIGATOR_PROTO_DIR", DEFAULT_PROTO_DIR))
if not PROTO_DIR.exists():
    PROTO_DIR = REPO_PROTO_DIR
DEFAULT_ADDR = "navigator.navigator.svc.cluster.local:8080"


def generate_protos() -> pathlib.Path:
    out_dir = pathlib.Path(tempfile.mkdtemp(prefix="navigator-protos-"))
    proto_include = importlib.resources.files("grpc_tools") / "_proto"

    result = protoc.main(
        [
            "protoc",
            f"-I{PROTO_DIR}",
            f"-I{proto_include}",
            f"--python_out={out_dir}",
            f"--grpc_python_out={out_dir}",
            str(PROTO_DIR / "navigator.proto"),
            str(PROTO_DIR / "sandbox.proto"),
            str(PROTO_DIR / "datamodel.proto"),
        ]
    )
    if result != 0:
        raise RuntimeError(f"protoc failed with exit code {result}")
    return out_dir


def load_stubs(proto_out: pathlib.Path):
    sys.path.insert(0, str(proto_out))
    import datamodel_pb2  # noqa: WPS433
    import navigator_pb2  # noqa: WPS433
    import navigator_pb2_grpc  # noqa: WPS433

    return datamodel_pb2, navigator_pb2, navigator_pb2_grpc


def wait_for_not_found(
    stub, navigator_pb2, sandbox_name: str, timeout: float = 60.0
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            stub.GetSandbox(navigator_pb2.GetSandboxRequest(name=sandbox_name))
        except grpc.RpcError as exc:
            if exc.code() == grpc.StatusCode.NOT_FOUND:
                return
        time.sleep(1)
    raise AssertionError("sandbox record was not deleted within timeout")


def test_sandbox_grpc_crud() -> None:
    proto_out = generate_protos()
    datamodel_pb2, navigator_pb2, navigator_pb2_grpc = load_stubs(proto_out)

    addr = os.environ.get("NAVIGATOR_GRPC_ADDR", DEFAULT_ADDR)
    channel = grpc.insecure_channel(addr)
    stub = navigator_pb2_grpc.NavigatorStub(channel)

    spec = datamodel_pb2.SandboxSpec(
        template=datamodel_pb2.SandboxTemplate(
            agent_image="busybox:latest",
        )
    )

    create_resp = stub.CreateSandbox(navigator_pb2.CreateSandboxRequest(spec=spec))
    sandbox = create_resp.sandbox
    assert sandbox.id
    assert sandbox.name.startswith("sandbox-")

    get_resp = stub.GetSandbox(navigator_pb2.GetSandboxRequest(name=sandbox.name))
    assert get_resp.sandbox.id == sandbox.id
    assert get_resp.sandbox.name == sandbox.name

    list_resp = stub.ListSandboxes(navigator_pb2.ListSandboxesRequest(limit=100))
    ids = {item.id for item in list_resp.sandboxes}
    assert sandbox.id in ids

    delete_resp = stub.DeleteSandbox(
        navigator_pb2.DeleteSandboxRequest(name=sandbox.name)
    )
    assert delete_resp.deleted is True

    wait_for_not_found(stub, navigator_pb2, sandbox.name)
