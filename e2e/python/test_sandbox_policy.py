from __future__ import annotations

from typing import TYPE_CHECKING

from navigator._proto import datamodel_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable

    from navigator import Sandbox


def _policy_for_python_proxy_tests() -> sandbox_pb2.SandboxPolicy:
    return sandbox_pb2.SandboxPolicy(
        version=1,
        inference=sandbox_pb2.InferencePolicy(allowed_routing_hints=["local"]),
        filesystem=sandbox_pb2.FilesystemPolicy(
            include_workdir=True,
            read_only=["/usr", "/lib", "/etc", "/app"],
            read_write=["/sandbox", "/tmp"],
        ),
        landlock=sandbox_pb2.LandlockPolicy(compatibility="best_effort"),
        process=sandbox_pb2.ProcessPolicy(
            run_as_user="sandbox", run_as_group="sandbox"
        ),
        network_policies={
            "python": sandbox_pb2.NetworkPolicyRule(
                name="python",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(host="api.openai.com", port=443)
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/app/.venv/bin/python")],
            )
        },
    )


def test_policy_applies_to_exec_commands(
    sandbox: Callable[..., Sandbox],
) -> None:
    def current_user() -> str:
        import os
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name

    def write_allowed_files() -> str:
        from pathlib import Path

        Path("/sandbox/allowed.txt").write_text("ok")
        Path("/tmp/allowed.txt").write_text("ok")
        return "ok"

    spec = datamodel_pb2.SandboxSpec(policy=_policy_for_python_proxy_tests())

    with sandbox(spec=spec, delete_on_exit=True) as policy_sandbox:
        user_result = policy_sandbox.exec_python(current_user)
        assert user_result.exit_code == 0, user_result.stderr
        assert user_result.stdout.strip() == "sandbox"

        file_result = policy_sandbox.exec_python(write_allowed_files)
        assert file_result.exit_code == 0, file_result.stderr
        assert file_result.stdout.strip() == "ok"


def test_policy_blocks_unauthorized_proxy_connect(
    sandbox: Callable[..., Sandbox],
) -> None:
    def proxy_connect_status() -> str:
        import socket

        connection = socket.create_connection(("10.200.0.1", 3128), timeout=5)
        try:
            connection.sendall(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
            )
            return connection.recv(128).decode("latin1")
        finally:
            connection.close()

    spec = datamodel_pb2.SandboxSpec(policy=_policy_for_python_proxy_tests())
    with sandbox(spec=spec, delete_on_exit=True) as policy_sandbox:
        proxy_result = policy_sandbox.exec_python(proxy_connect_status)
        assert proxy_result.exit_code == 0, proxy_result.stderr
        assert "403" in proxy_result.stdout
