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
_CONNECT_L7_PORT = 19880


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


def _connect_l7_policy() -> sandbox_pb2.SandboxPolicy:
    """Policy with a CONNECT-eligible endpoint using L7 REST inspection."""
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
            "internal_l7": sandbox_pb2.NetworkPolicyRule(
                name="internal_l7",
                endpoints=[
                    sandbox_pb2.NetworkEndpoint(
                        host=_SANDBOX_IP,
                        port=_CONNECT_L7_PORT,
                        protocol="rest",
                        enforcement="enforce",
                        access="full",
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


def _connect_l7_echo_server_returns_auth_header():
    """Return a closure that starts an echo HTTP server and sends a CONNECT
    request through the proxy, returning what the server received."""

    def fn(proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> str:
        import os
        import socket
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class EchoHandler(BaseHTTPRequestHandler):
            """Echoes back the Authorization header received from the proxy."""

            def do_GET(self):
                auth = self.headers.get("Authorization", "MISSING")
                # Also include x-api-key for multi-header testing
                api_key = self.headers.get("x-api-key", "MISSING")
                body = f"auth={auth}\nx-api-key={api_key}".encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("0.0.0.0", int(target_port)), EchoHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        time.sleep(0.5)

        # Read the placeholder env var (the child process only sees placeholders)
        token = os.environ.get("ANTHROPIC_API_KEY", "NOT_SET")

        conn = socket.create_connection((proxy_host, int(proxy_port)), timeout=10)
        try:
            # 1. CONNECT through the proxy
            connect_req = (
                f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n\r\n"
            )
            conn.sendall(connect_req.encode())

            # Read CONNECT response
            connect_resp = b""
            while b"\r\n\r\n" not in connect_resp:
                chunk = conn.recv(256)
                if not chunk:
                    break
                connect_resp += chunk
            connect_status = connect_resp.decode("latin1")

            if "200" not in connect_status:
                return f"CONNECT failed: {connect_status.strip()}"

            # 2. Send HTTP request through the established tunnel
            # The proxy will do L7 inspection and rewrite placeholders
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n"
                f"Authorization: Bearer {token}\r\n"
                f"Connection: close\r\n\r\n"
            )
            conn.sendall(request.encode())

            # 3. Read the response from the echo server
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


def _connect_l7_echo_multiple_secrets():
    """Return a closure that tests multiple provider secrets are rewritten
    through the CONNECT L7 proxy path."""

    def fn(proxy_host: str, proxy_port: int, target_host: str, target_port: int) -> str:
        import os
        import socket
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class EchoHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                auth = self.headers.get("Authorization", "MISSING")
                api_key = self.headers.get("x-api-key", "MISSING")
                custom = self.headers.get("x-custom-token", "MISSING")
                body = f"auth={auth}\nx-api-key={api_key}\nx-custom-token={custom}".encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("0.0.0.0", int(target_port)), EchoHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        time.sleep(0.5)

        # Read placeholder env vars
        api_key = os.environ.get("MY_API_KEY", "NOT_SET")
        custom_token = os.environ.get("CUSTOM_SERVICE_TOKEN", "NOT_SET")

        conn = socket.create_connection((proxy_host, int(proxy_port)), timeout=10)
        try:
            connect_req = (
                f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n\r\n"
            )
            conn.sendall(connect_req.encode())

            connect_resp = b""
            while b"\r\n\r\n" not in connect_resp:
                chunk = conn.recv(256)
                if not chunk:
                    break
                connect_resp += chunk

            if "200" not in connect_resp.decode("latin1"):
                return f"CONNECT failed: {connect_resp.decode('latin1').strip()}"

            # Send request with multiple placeholder headers
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n"
                f"Authorization: Bearer {api_key}\r\n"
                f"x-api-key: {api_key}\r\n"
                f"x-custom-token: {custom_token}\r\n"
                f"Connection: close\r\n\r\n"
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


def test_provider_secret_resolved_via_connect_l7_proxy(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Real secret reaches the destination through a CONNECT tunnel with L7 REST
    inspection.

    A dummy HTTP echo server runs inside the sandbox. The child process sends a
    CONNECT request through the proxy and then an HTTP request carrying the
    placeholder env var in the Authorization header. The proxy performs L7
    inspection and rewrites the placeholder to the real credential before
    forwarding. The echo server reflects the received header back so we can
    assert the *real* secret arrived at the destination.
    """
    with provider(
        sandbox_client._stub,
        name="e2e-test-connect-l7-rewrite",
        provider_type="claude",
        credentials={"ANTHROPIC_API_KEY": "sk-connect-l7-secret-99"},
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_connect_l7_policy(),
            providers=[provider_name],
        )

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(
                _connect_l7_echo_server_returns_auth_header(),
                args=("10.200.0.1", 3128, _SANDBOX_IP, _CONNECT_L7_PORT),
            )
            assert result.exit_code == 0, result.stderr
            # The echo server should have received the real secret
            assert "200 OK" in result.stdout, (
                f"Expected 200 OK in response, got: {result.stdout}"
            )
            assert "auth=Bearer sk-connect-l7-secret-99" in result.stdout, (
                f"Real secret not found in echo response: {result.stdout}"
            )
            # The placeholder must NOT appear in the response
            assert "nemo-placeholder:env:ANTHROPIC_API_KEY" not in result.stdout


def test_provider_multiple_secrets_resolved_via_connect_l7_proxy(
    sandbox: Callable[..., Sandbox],
    sandbox_client: SandboxClient,
) -> None:
    """Multiple provider secrets are rewritten through CONNECT L7 proxy.

    Verifies that when a request carries several headers each containing a
    different provider placeholder, every placeholder is resolved to the
    corresponding real credential by the time the request reaches the
    destination.
    """
    with provider(
        sandbox_client._stub,
        name="e2e-test-connect-l7-multi",
        provider_type="generic",
        credentials={
            "MY_API_KEY": "real-api-key-abc",
            "CUSTOM_SERVICE_TOKEN": "real-custom-token-xyz",
        },
    ) as provider_name:
        spec = datamodel_pb2.SandboxSpec(
            policy=_connect_l7_policy(),
            providers=[provider_name],
        )

        with sandbox(spec=spec, delete_on_exit=True) as sb:
            result = sb.exec_python(
                _connect_l7_echo_multiple_secrets(),
                args=("10.200.0.1", 3128, _SANDBOX_IP, _CONNECT_L7_PORT),
            )
            assert result.exit_code == 0, result.stderr
            assert "200 OK" in result.stdout, (
                f"Expected 200 OK in response, got: {result.stdout}"
            )
            # Bearer prefix + exact match for Authorization header
            assert "auth=Bearer real-api-key-abc" in result.stdout, (
                f"API key not rewritten in Authorization header: {result.stdout}"
            )
            # Exact match for x-api-key (no Bearer prefix)
            assert "x-api-key=real-api-key-abc" in result.stdout, (
                f"API key not rewritten in x-api-key header: {result.stdout}"
            )
            # Exact match for x-custom-token
            assert "x-custom-token=real-custom-token-xyz" in result.stdout, (
                f"Custom token not rewritten in x-custom-token header: {result.stdout}"
            )
            # No placeholders should appear
            assert "nemo-placeholder:env:" not in result.stdout


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
