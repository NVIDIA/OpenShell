# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""E2e tests for server mTLS enforcement.

These tests verify that the Navigator server correctly requires valid client
certificates signed by the cluster CA.  Only callers presenting the provisioned
mTLS client cert should be able to reach the Navigator gRPC API; all other
connection attempts must be rejected.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from urllib.parse import urlparse

import grpc
import pytest

from navigator._proto import navigator_pb2, navigator_pb2_grpc

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _xdg_config_home() -> pathlib.Path:
    configured = os.environ.get("XDG_CONFIG_HOME")
    if configured:
        return pathlib.Path(configured)
    return pathlib.Path.home() / ".config"


def _resolve_cluster_name() -> str:
    env_cluster = os.environ.get("NAVIGATOR_CLUSTER")
    if env_cluster:
        return env_cluster
    active_file = _xdg_config_home() / "navigator" / "active_cluster"
    return active_file.read_text().strip()


def _cluster_metadata(cluster_name: str) -> dict:
    metadata_path = (
        _xdg_config_home() / "navigator" / "clusters" / f"{cluster_name}_metadata.json"
    )
    return json.loads(metadata_path.read_text())


def _mtls_dir(cluster_name: str) -> pathlib.Path:
    return _xdg_config_home() / "navigator" / "clusters" / cluster_name / "mtls"


def _generate_self_signed_cert(
    tmpdir: pathlib.Path,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Generate a self-signed cert+key pair that is NOT signed by the cluster CA."""
    cert_path = tmpdir / "rogue.crt"
    key_path = tmpdir / "rogue.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-sha256",
            "-nodes",
            "-days",
            "1",
            "-newkey",
            "rsa:2048",
            "-subj",
            "/O=rogue/CN=rogue-client",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ],
        check=True,
        capture_output=True,
    )
    return cert_path, key_path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def cluster_name() -> str:
    name = _resolve_cluster_name()
    if not name:
        pytest.skip("no active cluster configured")
    return name


@pytest.fixture(scope="session")
def server_endpoint(cluster_name: str) -> tuple[str, int, str]:
    """Return (host, port, scheme) for the Navigator server."""
    metadata = _cluster_metadata(cluster_name)
    parsed = urlparse(metadata["gateway_endpoint"])
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 8080)
    return host, port, parsed.scheme


@pytest.fixture(scope="session")
def mtls_certs(
    cluster_name: str, server_endpoint: tuple[str, int, str]
) -> tuple[bytes, bytes, bytes]:
    """Return (ca_pem, cert_pem, key_pem) for the provisioned mTLS client."""
    _, _, scheme = server_endpoint
    if scheme != "https":
        pytest.skip("server is not using TLS; mTLS tests require an HTTPS endpoint")
    mtls = _mtls_dir(cluster_name)
    ca = (mtls / "ca.crt").read_bytes()
    cert = (mtls / "tls.crt").read_bytes()
    key = (mtls / "tls.key").read_bytes()
    return ca, cert, key


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestServerMtlsEnforcement:
    """Verify the server rejects callers without a valid client certificate."""

    def test_authenticated_client_succeeds(
        self,
        server_endpoint: tuple[str, int, str],
        mtls_certs: tuple[bytes, bytes, bytes],
    ) -> None:
        """A client presenting the correct mTLS cert can call Health."""
        host, port, _ = server_endpoint
        ca, cert, key = mtls_certs

        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca,
            private_key=key,
            certificate_chain=cert,
        )
        channel = grpc.secure_channel(f"{host}:{port}", credentials)
        try:
            stub = navigator_pb2_grpc.NavigatorStub(channel)
            response = stub.Health(navigator_pb2.HealthRequest(), timeout=10)
            assert response.status == navigator_pb2.SERVICE_STATUS_HEALTHY
        finally:
            channel.close()

    def test_no_client_cert_rejected(
        self,
        server_endpoint: tuple[str, int, str],
        mtls_certs: tuple[bytes, bytes, bytes],
    ) -> None:
        """A client that trusts the CA but presents no client cert is rejected."""
        host, port, _ = server_endpoint
        ca, _, _ = mtls_certs

        # Only provide the CA for server verification -- no client cert/key.
        credentials = grpc.ssl_channel_credentials(root_certificates=ca)
        channel = grpc.secure_channel(f"{host}:{port}", credentials)
        try:
            stub = navigator_pb2_grpc.NavigatorStub(channel)
            with pytest.raises(grpc.RpcError) as exc_info:
                stub.Health(navigator_pb2.HealthRequest(), timeout=10)
            # The server should terminate the TLS handshake or return
            # UNAVAILABLE because the client did not present a certificate.
            assert exc_info.value.code() in (
                grpc.StatusCode.UNAVAILABLE,
                grpc.StatusCode.UNKNOWN,
            ), f"expected UNAVAILABLE or UNKNOWN, got {exc_info.value.code()}"
        finally:
            channel.close()

    def test_wrong_client_cert_rejected(
        self,
        server_endpoint: tuple[str, int, str],
        mtls_certs: tuple[bytes, bytes, bytes],
    ) -> None:
        """A client presenting a cert signed by a different CA is rejected."""
        host, port, _ = server_endpoint
        ca, _, _ = mtls_certs

        with tempfile.TemporaryDirectory() as tmpdir:
            rogue_cert_path, rogue_key_path = _generate_self_signed_cert(
                pathlib.Path(tmpdir)
            )
            rogue_cert = rogue_cert_path.read_bytes()
            rogue_key = rogue_key_path.read_bytes()

        credentials = grpc.ssl_channel_credentials(
            root_certificates=ca,
            private_key=rogue_key,
            certificate_chain=rogue_cert,
        )
        channel = grpc.secure_channel(f"{host}:{port}", credentials)
        try:
            stub = navigator_pb2_grpc.NavigatorStub(channel)
            with pytest.raises(grpc.RpcError) as exc_info:
                stub.Health(navigator_pb2.HealthRequest(), timeout=10)
            assert exc_info.value.code() in (
                grpc.StatusCode.UNAVAILABLE,
                grpc.StatusCode.UNKNOWN,
            ), f"expected UNAVAILABLE or UNKNOWN, got {exc_info.value.code()}"
        finally:
            channel.close()

    def test_plaintext_connection_rejected(
        self,
        server_endpoint: tuple[str, int, str],
        mtls_certs: tuple[bytes, bytes, bytes],
    ) -> None:
        """A plaintext (non-TLS) connection to the server port is rejected."""
        host, port, _ = server_endpoint
        # Ensure we have certs loaded (so the test isn't skipped for non-TLS).
        _ = mtls_certs

        channel = grpc.insecure_channel(f"{host}:{port}")
        try:
            stub = navigator_pb2_grpc.NavigatorStub(channel)
            with pytest.raises(grpc.RpcError) as exc_info:
                stub.Health(navigator_pb2.HealthRequest(), timeout=10)
            # Plaintext to a TLS port will fail at the transport level.
            assert exc_info.value.code() in (
                grpc.StatusCode.UNAVAILABLE,
                grpc.StatusCode.UNKNOWN,
                grpc.StatusCode.INTERNAL,
            ), f"expected transport failure, got {exc_info.value.code()}"
        finally:
            channel.close()
