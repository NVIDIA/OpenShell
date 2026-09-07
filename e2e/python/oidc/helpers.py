# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for OIDC e2e tests.

Provides Keycloak token acquisition, gRPC channel setup, and JWT utilities.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request
from pathlib import Path

import grpc

from openshell._proto import openshell_pb2_grpc

KEYCLOAK_REALM = "openshell"


def _xdg_config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def keycloak_url() -> str:
    """Derive the Keycloak URL from the gateway's stored OIDC issuer.

    The server validates the issuer claim in JWTs, so the token must be
    requested from the same base URL the server was configured with
    (typically the host IP, not localhost).
    """
    if url := os.environ.get("OPENSHELL_KEYCLOAK_URL"):
        return url
    if issuer := os.environ.get("OPENSHELL_E2E_OIDC_ISSUER"):
        idx = issuer.find("/realms/")
        if idx > 0:
            return issuer[:idx]
    cluster_name = os.environ.get("OPENSHELL_GATEWAY", "openshell")
    metadata_path = (
        _xdg_config_home() / "openshell" / "gateways" / cluster_name / "metadata.json"
    )
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
        issuer = metadata.get("oidc_issuer", "")
        if issuer:
            idx = issuer.find("/realms/")
            if idx > 0:
                return issuer[:idx]
    return "http://localhost:8180"


TOKEN_ENDPOINT = (
    f"{keycloak_url()}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
)


def _gateway_endpoint() -> tuple[str, bool]:
    """Read the active gateway endpoint from metadata."""
    if endpoint := os.environ.get("OPENSHELL_E2E_OIDC_GATEWAY_ENDPOINT"):
        return endpoint, endpoint.startswith("https://")
    cluster_name = os.environ.get("OPENSHELL_GATEWAY", "openshell")
    metadata_path = (
        _xdg_config_home() / "openshell" / "gateways" / cluster_name / "metadata.json"
    )
    metadata = json.loads(metadata_path.read_text())
    endpoint = metadata["gateway_endpoint"]
    is_tls = endpoint.startswith("https://")
    return endpoint, is_tls


def _mtls_dir() -> Path:
    cluster_name = os.environ.get("OPENSHELL_GATEWAY", "openshell")
    return _xdg_config_home() / "openshell" / "gateways" / cluster_name / "mtls"


def _token_request(data: dict[str, str]) -> str:
    """POST to the Keycloak token endpoint and return the access token."""
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(TOKEN_ENDPOINT, data=encoded)
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.loads(resp.read())
    return body["access_token"]


def get_token(
    username: str,
    password: str,
    *,
    client_id: str = "openshell-cli",
    scopes: str | None = None,
) -> str:
    """Get an access token from Keycloak via password grant."""
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password,
    }
    if scopes:
        data["scope"] = scopes
    return _token_request(data)


def get_ci_token(
    *,
    client_id: str = "openshell-ci",
    client_secret: str = "ci-test-secret",
) -> str:
    """Get an access token via client credentials grant."""
    return _token_request(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
    )


def grpc_channel() -> grpc.Channel:
    """Create a gRPC channel to the gateway over its configured TLS transport."""
    endpoint, is_tls = _gateway_endpoint()
    parsed = urllib.parse.urlparse(endpoint)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if is_tls else 80)
    target = f"{host}:{port}"

    if is_tls:
        if ca_path := os.environ.get("OPENSHELL_E2E_GATEWAY_CA_CERT"):
            creds = grpc.ssl_channel_credentials(
                root_certificates=Path(ca_path).read_bytes()
            )
        else:
            mtls = _mtls_dir()
            creds = grpc.ssl_channel_credentials(
                root_certificates=(mtls / "ca.crt").read_bytes(),
                private_key=(mtls / "tls.key").read_bytes(),
                certificate_chain=(mtls / "tls.crt").read_bytes(),
            )
        return grpc.secure_channel(target, creds)
    return grpc.insecure_channel(target)


def stub_with_token(
    token: str,
) -> tuple[openshell_pb2_grpc.OpenShellStub, list[tuple[str, str]]]:
    """Create a gRPC stub that injects a Bearer token."""
    channel = grpc_channel()
    return openshell_pb2_grpc.OpenShellStub(channel), [
        ("authorization", f"Bearer {token}")
    ]


def extract_sub(token: str) -> str:
    """Extract the 'sub' claim from a JWT access token."""
    payload = token.split(".")[1]
    padded = payload + "=" * (4 - len(payload) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    claims = json.loads(decoded)
    return claims["sub"]
