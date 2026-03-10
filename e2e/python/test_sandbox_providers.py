# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""E2E tests for supervisor-managed provider placeholders in sandboxes.

Provider credentials are fetched at runtime by the sandbox supervisor via the
GetSandboxProviderEnvironment gRPC call. Sandboxed child processes should see
placeholder values, while the supervisor proxy resolves those placeholders back
to the real credentials on outbound requests. Credentials must still never be
present in the persisted sandbox spec environment map.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

import grpc
import pytest

from openshell._proto import datamodel_pb2, navigator_pb2, sandbox_pb2

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from openshell import Sandbox, SandboxClient


def _default_policy() -> sandbox_pb2.SandboxPolicy:
    return sandbox_pb2.SandboxPolicy(
        version=1,
        filesystem=sandbox_pb2.FilesystemPolicy(
            include_workdir=True,
            read_only=["/usr", "/lib", "/etc", "/app"],
            read_write=["/sandbox", "/tmp"],
        ),
        landlock=sandbox_pb2.LandlockPolicy(compatibility="best_effort"),
        process=sandbox_pb2.ProcessPolicy(
            run_as_user="sandbox", run_as_group="sandbox"
        ),
    )


@contextmanager
def provider(
    stub: object,
    *,
    name: str,
    provider_type: str,
    credentials: dict[str, str],
) -> Iterator[str]:
    """Create a provider for the duration of the block, then delete it."""
    # Clean up any leftover from a previous run.
    _delete_provider(stub, name)
    stub.CreateProvider(
        navigator_pb2.CreateProviderRequest(
            provider=datamodel_pb2.Provider(
                name=name,
                type=provider_type,
                credentials=credentials,
            )
        )
    )
    try:
        yield name
    finally:
        _delete_provider(stub, name)


def _delete_provider(stub: object, name: str) -> None:
    """Delete a provider, ignoring not-found errors."""
    try:
        stub.DeleteProvider(navigator_pb2.DeleteProviderRequest(name=name))
    except grpc.RpcError as exc:
        if hasattr(exc, "code") and exc.code() == grpc.StatusCode.NOT_FOUND:
            pass
        else:
            raise


_SANDBOX_IP = "10.200.0.2"
_FORWARD_PROXY_PORT = 19879


def _proxy_policy() -> sandbox_pb2.SandboxPolicy:
    return sandbox_pb2.SandboxPolicy(
        version=1,
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
            "internal_http": sandbox_pb2.NetworkPolicyRule(
                name="internal_http",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host=_SANDBOX_IP,
                        port=_FORWARD_PROXY_PORT,
                        allowed_ips=["10.200.0.0/24"],
                    )
                ],
                binaries=[sandbox_pb2.NetworkBinary(path="/**")],
            )
        },
    )


def _forward_proxy_reads_env_and_returns_auth_header():
    def fn(proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> str:
        import os
        import socket
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                auth = self.headers.get("Authorization", "MISSING")
                body = auth.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("0.0.0.0", int(target_port)), Handler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        time.sleep(0.5)

        token = os.environ["ANTHROPIC_API_KEY"]
        conn = socket.create_connection((proxy_host, int(proxy_port)), timeout=10)
        try:
            request = (
                f"GET http://{target_host}:{target_port}/ HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n"
                f"Authorization: Bearer {token}\r\n"
                "Connection: close\r\n\r\n"
            )
            conn.sendall(request.encode())
            data = b""
            conn.settimeout(5)
            while True:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            return data.decode("latin1")
        finally:
            conn.close()
            server.server_close()

    return fn


def test_provider_credentials_available_as_env_vars(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Sandbox child processes see provider env vars as placeholders."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-provider-env",
        provider_type="claude",
        credentials={"ANTHROPIC_API_KEY": "sk-e2e-test-key-12345"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        def read_env_var() -> str:
            import os

            return os.environ.get("ANTHROPIC_API_KEY", "NOT_SET")

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_env_var)
            assert result.exit_code == 0, result.stderr
            value = result.stdout.strip()
            assert value == "nemo-placeholder:env:ANTHROPIC_API_KEY"
            assert value != "sk-e2e-test-key-12345"


def test_generic_provider_credentials_available_as_env_vars(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Generic provider env vars are placeholders, not raw secrets."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-generic-provider-env",
        provider_type="generic",
        credentials={
            "CUSTOM_SERVICE_TOKEN": "token-generic-123",
            "CUSTOM_SERVICE_URL": "https://internal.example.test/api",
        },
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        def read_generic_env_vars() -> str:
            import os

            token = os.environ.get("CUSTOM_SERVICE_TOKEN", "NOT_SET")
            url = os.environ.get("CUSTOM_SERVICE_URL", "NOT_SET")
            return f"{token}|{url}"

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_generic_env_vars)
            assert result.exit_code == 0, result.stderr
            assert (
                result.stdout.strip()
                == "nemo-placeholder:env:CUSTOM_SERVICE_TOKEN|nemo-placeholder:env:CUSTOM_SERVICE_URL"
            )


def test_nvidia_provider_injects_nvidia_api_key_env_var(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """NVIDIA provider projects a placeholder env value into child processes."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-nvidia-provider-env",
        provider_type="nvidia",
        credentials={"NVIDIA_API_KEY": "nvapi-e2e-test-key"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        def read_nvidia_key() -> str:
            import os

            return os.environ.get("NVIDIA_API_KEY", "NOT_SET")

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(read_nvidia_key)
            assert result.exit_code == 0, result.stderr
            assert result.stdout.strip() == "nemo-placeholder:env:NVIDIA_API_KEY"


def test_provider_placeholder_is_resolved_by_proxy_on_outbound_request(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    with provider(
        sandbox_client._stub,
        name="e2e-test-provider-proxy-rewrite",
        provider_type="claude",
        credentials={"ANTHROPIC_API_KEY": "sk-proxy-rewrite-12345"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_proxy_policy(),
            providers=[provider_name],
        )

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(
                _forward_proxy_reads_env_and_returns_auth_header(),
                args=("10.200.0.1", 3128, _SANDBOX_IP, _FORWARD_PROXY_PORT),
            )
            assert result.exit_code == 0, result.stderr
            assert "200 OK" in result.stdout
            assert "Bearer sk-proxy-rewrite-12345" in result.stdout
            assert "nemo-placeholder:env:ANTHROPIC_API_KEY" not in result.stdout


def test_ssh_handshake_secret_not_visible_in_exec_environment(
    sandbox: Callable[..., Sandbox],
) -> None:
    def read_handshake_secret() -> str:
        import os

        return os.environ.get("NEMOCLAW_SSH_HANDSHAKE_SECRET", "NOT_SET")

    with sandbox(delete_on_exit=True) as sb:
        result = sb.exec_python(read_handshake_secret)
        assert result.exit_code == 0, result.stderr
        assert result.stdout.strip() == "NOT_SET"


def test_create_sandbox_rejects_unknown_provider(
    sandbox_client: SandboxClient,
) -> None:
    """CreateSandbox fails fast when a provider name does not exist."""
    spec = datamodel_pb2.SandboxSpec(
        policy=_default_policy(),
        providers=["nonexistent-provider-xyz"],
    )
    with pytest.raises(grpc.RpcError) as exc_info:
        sandbox_client.create(spec=spec)

    assert exc_info.value.code() == grpc.StatusCode.FAILED_PRECONDITION
    assert "nonexistent-provider-xyz" in (exc_info.value.details() or "")


def test_credentials_not_in_persisted_spec_environment(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Provider credentials should NOT appear in the sandbox spec's environment map."""
    with provider(
        sandbox_client._stub,
        name="e2e-test-no-persist",
        provider_type="claude",
        credentials={"ANTHROPIC_API_KEY": "sk-should-not-persist"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_default_policy(),
            providers=[provider_name],
        )

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            # Fetch the sandbox record from the server and inspect spec.environment.
            fetched = sandbox_client._stub.GetSandbox(
                navigator_pb2.GetSandboxRequest(name=sb.sandbox.name)
            )
            persisted_env = dict(fetched.sandbox.spec.environment)
            assert "ANTHROPIC_API_KEY" not in persisted_env, (
                "credentials should not be persisted in sandbox spec environment"
            )


# ---------------------------------------------------------------------------
# Provider update merge semantics
# ---------------------------------------------------------------------------


def test_update_provider_preserves_unset_credentials_and_config(
    sandbox_client: SandboxClient,
) -> None:
    """Updating one credential must not clobber other credentials or config."""
    stub = sandbox_client._stub
    name = "merge-test-preserve"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            navigator_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="generic",
                    credentials={"KEY_A": "val-a", "KEY_B": "val-b"},
                    config={"BASE_URL": "https://example.com"},
                )
            )
        )

        # Update only KEY_A; send empty config map (= no change).
        stub.UpdateProvider(
            navigator_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="",
                    credentials={"KEY_A": "rotated-a"},
                )
            )
        )

        got = stub.GetProvider(navigator_pb2.GetProviderRequest(name=name))
        p = got.provider
        assert p.credentials["KEY_A"] == "rotated-a"
        assert p.credentials["KEY_B"] == "val-b", "KEY_B should be preserved"
        assert p.config["BASE_URL"] == "https://example.com", (
            "config should be preserved"
        )
    finally:
        _delete_provider(stub, name)


def test_update_provider_empty_maps_preserves_all(
    sandbox_client: SandboxClient,
) -> None:
    """Sending empty credential and config maps should be a no-op."""
    stub = sandbox_client._stub
    name = "merge-test-noop"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            navigator_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="generic",
                    credentials={"TOKEN": "secret"},
                    config={"URL": "https://api.example.com"},
                )
            )
        )

        stub.UpdateProvider(
            navigator_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="",
                )
            )
        )

        got = stub.GetProvider(navigator_pb2.GetProviderRequest(name=name))
        p = got.provider
        assert p.credentials["TOKEN"] == "secret"
        assert p.config["URL"] == "https://api.example.com"
    finally:
        _delete_provider(stub, name)


def test_update_provider_merges_config_preserves_credentials(
    sandbox_client: SandboxClient,
) -> None:
    """Updating only config should not touch credentials."""
    stub = sandbox_client._stub
    name = "merge-test-config-only"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            navigator_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="generic",
                    credentials={"API_KEY": "original-key"},
                    config={"ENDPOINT": "https://old.example.com"},
                )
            )
        )

        # Send only config update, empty credentials map.
        stub.UpdateProvider(
            navigator_pb2.UpdateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="",
                    config={"ENDPOINT": "https://new.example.com"},
                )
            )
        )

        got = stub.GetProvider(navigator_pb2.GetProviderRequest(name=name))
        p = got.provider
        assert p.credentials["API_KEY"] == "original-key", (
            "credentials should be untouched"
        )
        assert p.config["ENDPOINT"] == "https://new.example.com"
    finally:
        _delete_provider(stub, name)


def test_update_provider_rejects_type_change(
    sandbox_client: SandboxClient,
) -> None:
    """Attempting to change a provider's type must be rejected."""
    stub = sandbox_client._stub
    name = "merge-test-type-reject"
    _delete_provider(stub, name)

    try:
        stub.CreateProvider(
            navigator_pb2.CreateProviderRequest(
                provider=datamodel_pb2.Provider(
                    name=name,
                    type="generic",
                    credentials={"KEY": "val"},
                )
            )
        )

        with pytest.raises(grpc.RpcError) as exc_info:
            stub.UpdateProvider(
                navigator_pb2.UpdateProviderRequest(
                    provider=datamodel_pb2.Provider(
                        name=name,
                        type="nvidia",
                    )
                )
            )
        assert exc_info.value.code() == grpc.StatusCode.INVALID_ARGUMENT
        assert "type cannot be changed" in exc_info.value.details()
    finally:
        _delete_provider(stub, name)
